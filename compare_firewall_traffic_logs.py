"""
compare_firewall_traffic_logs.py
--------------------
index=firewall src_ip=10.10.0.0/19 action=allowed bytes_in=0 
| stats count as Occurrence_Count, 
        sum(bytes_out) as Total_Bytes_Out, 
        values(dvc) as Device_ID, 
        values(rule) as Rules, 
        latest(_time) as Last_Seen 
        by src_ip, dest_ip, dest_port
| eval Last_Seen=strftime(Last_Seen, "%Y-%m-%d %H:%M:%S")
| sort - Occurrence_Count
| head 200
| table src_ip, dest_ip, dest_port, Device_ID, Rules, Occurrence_Count, Total_Bytes_Out, Last_Seen

====
Compares 4 Splunk-exported or Panorama PAN firewall CSVs (yesterday/today x bytes_in/no_bytes_in)
and produces an Excel report flagging which src_ip / dest_ip / dest_port flows:

  - BROKEN TODAY      : had bytes_in > 0 yesterday, but 0 bytes_in today  (real issue)
  - RECOVERED TODAY   : had 0 bytes_in yesterday, but bytes_in > 0 today  (fixed / improved)
  - STABLE - WORKING  : bytes_in > 0 both days
  - STABLE - NO BYTES : 0 bytes_in both days (chronic, may be expected/decommissioned)
  - MISSING TODAY     : seen yesterday (with bytes), no record at all today (no traffic attempted)
  - NEW TODAY         : seen today only, no record at all yesterday

USAGE
-----
1. Put this script in the SAME folder as your 4 exported CSV files.
2. Run it with no arguments:

       python compare_pan_logs.py

   It auto-detects which file is which by looking at the filename for the
   keywords "today" / "yesterday" and "no" + "byte" (meaning a no-bytes-in
   file; absence of "no" means a bytes-in/successful file). This matches
   names like:
       "yesterday successful list with bytes in to compare.csv"
       "Today successful list with bytes in.csv"
       "Today-no-bytes-in list need to compare.csv"
       "yesterday-no-bytes-in list.csv"

   If auto-detection can't confidently match all 4 files (e.g. you renamed
   them to something unrecognizable), the script lists what it found and
   exits -- at that point just pass the 4 paths explicitly instead:

       python compare_pan_logs.py yesterday_bytes.csv today_bytes.csv yesterday_nobytes.csv today_nobytes.csv

Output: pan_fw_comparison_report.xlsx, written to the SAME folder as this script.
"""

import sys
import glob
import os
import pandas as pd
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# Folder this script lives in -- all auto-detected CSVs and the output
# report are read/written relative to here, regardless of your current
# working directory when you run `python compare_pan_logs.py`.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

OUTPUT_FILE = os.path.join(SCRIPT_DIR, "pan_fw_comparison_report.xlsx")

# Columns we expect from the Splunk query (case-insensitive match).
# src_ip / dest_ip / dest_port form the comparison key.
KEY_COLUMNS = ["src_ip", "dest_ip", "dest_port"]
CONTEXT_COLUMNS = ["Device_ID", "Rules", "Occurrence_Count", "Total_Bytes_Out", "Last_Seen"]

# ----------------------------------------------------------------------


def auto_detect_files():
    """Scan SCRIPT_DIR for the 4 CSVs based on filename keywords, matching the
    naming pattern from the Splunk export (e.g. 'Today-no-bytes-in list.csv',
    'yesterday successful list with bytes in.csv')."""
    csv_paths = glob.glob(os.path.join(SCRIPT_DIR, "*.csv"))
    if not csv_paths:
        raise FileNotFoundError(
            f"No .csv files found in {SCRIPT_DIR}. "
            f"Put this script in the same folder as your 4 exported CSVs."
        )

    buckets = {
        "yesterday_bytes": None,
        "today_bytes": None,
        "yesterday_nobytes": None,
        "today_nobytes": None,
    }

    for path in csv_paths:
        name = os.path.basename(path).lower()
        is_today = "today" in name
        is_yesterday = "yesterday" in name
        # "no-bytes-in" / "no_bytes_in" / "no bytes in" all contain "no" immediately
        # followed eventually by "byte" -- simplest reliable signal is "no" + "byte"
        # both present, vs a bytes-in file which has "byte" but not "no byte".
        is_no_bytes = "no" in name and "byte" in name and (
            "nobyte" in name.replace(" ", "").replace("-", "").replace("_", "")
        )

        if is_yesterday and is_no_bytes:
            key = "yesterday_nobytes"
        elif is_yesterday and not is_no_bytes:
            key = "yesterday_bytes"
        elif is_today and is_no_bytes:
            key = "today_nobytes"
        elif is_today and not is_no_bytes:
            key = "today_bytes"
        else:
            continue  # filename didn't clearly match any bucket

        if buckets[key] is not None:
            print(f"WARNING: multiple files matched '{key}': "
                  f"'{buckets[key]}' and '{path}'. Keeping the first; "
                  f"rename files or pass paths explicitly if this is wrong.")
            continue
        buckets[key] = path

    missing = [k for k, v in buckets.items() if v is None]
    if missing:
        print("Could not confidently auto-detect all 4 files.")
        print(f"CSV files found in folder: {[os.path.basename(p) for p in csv_paths]}")
        print(f"Still missing: {missing}")
        print()
        print("Re-run passing the 4 paths explicitly, in this order:")
        print("  python compare_pan_logs.py yesterday_bytes.csv today_bytes.csv "
              "yesterday_nobytes.csv today_nobytes.csv")
        sys.exit(1)

    print("Auto-detected files:")
    for k, v in buckets.items():
        print(f"  {k:20s} -> {os.path.basename(v)}")
    print()

    return (buckets["yesterday_bytes"], buckets["today_bytes"],
            buckets["yesterday_nobytes"], buckets["today_nobytes"])


def load_csv(path):
    """Load a CSV and normalize column names to match KEY_COLUMNS/CONTEXT_COLUMNS
    regardless of case/whitespace differences in the source file."""
    df = pd.read_csv(path, dtype=str, encoding="utf-8-sig").fillna("")
    df.columns = [c.strip() for c in df.columns]

    # Build a case-insensitive lookup so "Src_IP", "SRC_IP", "src_ip" all resolve
    lower_map = {c.lower(): c for c in df.columns}
    rename = {}
    for wanted in KEY_COLUMNS + CONTEXT_COLUMNS:
        if wanted.lower() in lower_map and lower_map[wanted.lower()] != wanted:
            rename[lower_map[wanted.lower()]] = wanted
    if rename:
        df = df.rename(columns=rename)

    missing_keys = [k for k in KEY_COLUMNS if k not in df.columns]
    if missing_keys:
        raise ValueError(
            f"File '{path}' is missing required key column(s): {missing_keys}. "
            f"Found columns: {list(df.columns)}"
        )

    for c in KEY_COLUMNS:
        df[c] = df[c].astype(str).str.strip()

    df["_key"] = df["src_ip"] + " | " + df["dest_ip"] + " | " + df["dest_port"]
    return df


def build_lookup(df):
    """key -> row (first occurrence) as a dict, for pulling context columns later."""
    lookup = {}
    for _, row in df.iterrows():
        if row["_key"] not in lookup:
            lookup[row["_key"]] = row
    return lookup


def classify(y_bytes, t_bytes, y_nobytes, t_nobytes):
    y_bytes_keys = set(y_bytes["_key"])
    t_bytes_keys = set(t_bytes["_key"])
    y_nobytes_keys = set(y_nobytes["_key"])
    t_nobytes_keys = set(t_nobytes["_key"])

    all_keys = y_bytes_keys | t_bytes_keys | y_nobytes_keys | t_nobytes_keys

    categories = {
        "BROKEN TODAY": [],
        "RECOVERED TODAY": [],
        "STABLE - WORKING": [],
        "STABLE - NO BYTES": [],
        "MISSING TODAY": [],
        "NEW TODAY": [],
    }

    for key in all_keys:
        seen_y_bytes = key in y_bytes_keys
        seen_t_bytes = key in t_bytes_keys
        seen_y_nobytes = key in y_nobytes_keys
        seen_t_nobytes = key in t_nobytes_keys

        seen_yesterday = seen_y_bytes or seen_y_nobytes
        seen_today = seen_t_bytes or seen_t_nobytes

        if seen_y_bytes and seen_t_nobytes:
            categories["BROKEN TODAY"].append(key)
        elif seen_y_nobytes and seen_t_bytes:
            categories["RECOVERED TODAY"].append(key)
        elif seen_y_bytes and seen_t_bytes:
            categories["STABLE - WORKING"].append(key)
        elif seen_y_nobytes and seen_t_nobytes:
            categories["STABLE - NO BYTES"].append(key)
        elif seen_yesterday and not seen_today:
            categories["MISSING TODAY"].append(key)
        elif seen_today and not seen_yesterday:
            categories["NEW TODAY"].append(key)

    return categories


def context_row(key, *lookups):
    """Return the first available context row for this key, checked in priority order."""
    for lookup in lookups:
        if key in lookup:
            return lookup[key]
    return None


def write_report(categories, y_bytes_lu, t_bytes_lu, y_nobytes_lu, t_nobytes_lu):
    wb = Workbook()
    wb.remove(wb.active)

    header_font = Font(name="Arial", bold=True, color="FFFFFF", size=11)
    body_font = Font(name="Arial", size=10)
    title_font = Font(name="Arial", bold=True, size=14)
    thin = Side(style="thin", color="D9D9D9")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)

    category_fill = {
        "BROKEN TODAY": "C00000",        # red
        "RECOVERED TODAY": "548235",     # green
        "STABLE - WORKING": "8EA9DB",    # blue
        "STABLE - NO BYTES": "A6A6A6",   # grey
        "MISSING TODAY": "BF8F00",       # amber
        "NEW TODAY": "7030A0",           # purple
    }

    cols = ["src_ip", "dest_ip", "dest_port"] + CONTEXT_COLUMNS

    # ---------------- Summary sheet ----------------
    ws = wb.create_sheet("Summary")
    ws["A1"] = "PAN Firewall - Bytes_In Comparison Report (Yesterday vs Today)"
    ws["A1"].font = title_font
    ws.merge_cells("A1:C1")

    ws["A3"] = "Category"
    ws["B3"] = "Count"
    ws["C3"] = "Meaning"
    for c in ("A3", "B3", "C3"):
        ws[c].font = header_font
        ws[c].fill = PatternFill("solid", fgColor="305496")

    meanings = {
        "BROKEN TODAY": "Had traffic yesterday, 0 bytes_in today -> investigate first",
        "RECOVERED TODAY": "Had 0 bytes_in yesterday, traffic restored today",
        "STABLE - WORKING": "Working both days, no action needed",
        "STABLE - NO BYTES": "0 bytes_in both days - chronic / possibly decommissioned",
        "MISSING TODAY": "Had traffic yesterday, no record at all today (flow absent)",
        "NEW TODAY": "No record yesterday, appears today only",
    }

    row_idx = 4
    cat_rows = {}
    for cat in categories:
        ws.cell(row=row_idx, column=1, value=cat).font = body_font
        ws.cell(row=row_idx, column=1).fill = PatternFill("solid", fgColor=category_fill[cat])
        ws.cell(row=row_idx, column=1).font = Font(name="Arial", bold=True, color="FFFFFF")
        # COUNTA formula referencing that category's own sheet (col A, data rows start at row 2)
        sheet_name = cat.title().replace(" ", "_")[:28]
        ws.cell(row=row_idx, column=2,
                 value=f"=COUNTA('{sheet_name}'!A2:A100000)")
        ws.cell(row=row_idx, column=3, value=meanings[cat]).font = body_font
        cat_rows[cat] = (row_idx, sheet_name)
        row_idx += 1

    ws.column_dimensions["A"].width = 22
    ws.column_dimensions["B"].width = 10
    ws.column_dimensions["C"].width = 62

    # ---------------- One sheet per category ----------------
    for cat, keys in categories.items():
        sheet_name = cat_rows[cat][1]
        cws = wb.create_sheet(sheet_name)

        for j, col_name in enumerate(cols, start=1):
            cell = cws.cell(row=1, column=j, value=col_name)
            cell.font = header_font
            cell.fill = PatternFill("solid", fgColor=category_fill[cat])
            cell.border = border

        r = 2
        for key in sorted(keys):
            row = context_row(key, t_bytes_lu, t_nobytes_lu, y_bytes_lu, y_nobytes_lu)
            src_ip, dest_ip, dest_port = key.split(" | ")
            values = [src_ip, dest_ip, dest_port]
            for c in CONTEXT_COLUMNS:
                values.append(row.get(c, "") if row is not None else "")
            for j, v in enumerate(values, start=1):
                cell = cws.cell(row=r, column=j, value=v)
                cell.font = body_font
                cell.border = border
            r += 1

        for j in range(1, len(cols) + 1):
            cws.column_dimensions[get_column_letter(j)].width = 20
        cws.freeze_panes = "A2"

    wb.save(OUTPUT_FILE)
    print(f"Report written to {OUTPUT_FILE}")


def main():
    if len(sys.argv) == 5:
        y_bytes_path, t_bytes_path, y_nobytes_path, t_nobytes_path = sys.argv[1:5]
    else:
        y_bytes_path, t_bytes_path, y_nobytes_path, t_nobytes_path = auto_detect_files()

    y_bytes = load_csv(y_bytes_path)
    t_bytes = load_csv(t_bytes_path)
    y_nobytes = load_csv(y_nobytes_path)
    t_nobytes = load_csv(t_nobytes_path)

    y_bytes_lu = build_lookup(y_bytes)
    t_bytes_lu = build_lookup(t_bytes)
    y_nobytes_lu = build_lookup(y_nobytes)
    t_nobytes_lu = build_lookup(t_nobytes)

    categories = classify(y_bytes, t_bytes, y_nobytes, t_nobytes)

    for cat, keys in categories.items():
        print(f"{cat}: {len(keys)} flow(s)")

    write_report(categories, y_bytes_lu, t_bytes_lu, y_nobytes_lu, t_nobytes_lu)


if __name__ == "__main__":
    main()
