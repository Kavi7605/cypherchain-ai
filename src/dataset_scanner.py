import os
import hashlib
import pandas as pd
import zipfile

def calculate_sha256(file_path):
    """Calculate SHA256 hash of a file."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(block)
    return sha256_hash.hexdigest()

def get_file_info(file_path):
    """Return dataset file info including type, size, hash, and metadata."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Path not found: {file_path}")

    size_bytes = os.path.getsize(file_path)
    checksum = calculate_sha256(file_path)
    ext = os.path.splitext(file_path)[1].lower()

    info = {
        "file_path": file_path,
        "size_bytes": size_bytes,
        "sha256": checksum,
        "type": None,
        "details": {}
    }

    if ext == ".csv":
        info["type"] = "CSV file"
        df = pd.read_csv(file_path, nrows=100)  # read first 100 rows
        info["details"] = {"columns": list(df.columns), "sample_rows": len(df)}

    elif ext == ".json":
        info["type"] = "JSON file"
        df = pd.read_json(file_path, lines=True, nrows=100)
        info["details"] = {"columns": list(df.columns), "sample_rows": len(df)}

    elif ext in [".xlsx", ".xls"]:
        info["type"] = "Excel file"
        df = pd.read_excel(file_path, nrows=100)
        info["details"] = {"columns": list(df.columns), "sample_rows": len(df)}

    elif ext == ".parquet":
        info["type"] = "Parquet file"
        df = pd.read_parquet(file_path)
        info["details"] = {"columns": list(df.columns), "total_rows": len(df)}

    elif ext == ".zip":
        info["type"] = "ZIP archive"
        with zipfile.ZipFile(file_path, 'r') as z:
            info["details"]["files_inside"] = [
                {"name": f, "size": z.getinfo(f).file_size} for f in z.namelist()
            ]
    else:
        info["type"] = "Unknown/other file format"

    return info

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python dataset_scanner.py <dataset_file>")
        sys.exit(1)

    path = sys.argv[1]
    try:
        report = get_file_info(path)
        print("\nDataset Scan Report")
        print("="*50)
        for k, v in report.items():
            print(f"{k}: {v}")
    except Exception as e:
        print(f"Error: {e}")
