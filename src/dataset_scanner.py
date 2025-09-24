import os
import hashlib
import pandas as pd
import zipfile
import numpy as np
import re

def calculate_sha256(file_path):
    """Calculate SHA256 hash of a file."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(block)
    return sha256_hash.hexdigest()

def detect_code_injection(value):
    """Detect suspicious code injection or SQL injection in text."""
    patterns = [
        r"(?i)\b(or|and)\b.+\b=\b",            # SQL logic
        r"\b(drop\s+table)\b",                 # SQL destructive
        r"\b(delete\s+from)\b",
        r"\b(insert\s+into)\b",
        r"\b(union\s+select)\b",
        r"eval\(",
        r"exec\(",
        r"system\(",
        r"base64,",
        r"<script>",
        r"alert\(",
        r"\.decode\(",
        r"import\s+os",
        r"os\.system\(",
        r";\s*--",                             # SQL comment/injection
        r"#\s*--",
        r"admin' OR '1'='1"
    ]
    for pat in patterns:
        if re.search(pat, str(value), re.IGNORECASE):
            return True
    return False

def detect_malicious_keywords(value):
    keywords = [
        "exploit", "backdoor", "trojan", "virus", "malware",
        "keylogger", "rootkit", "botnet", "phishing", "ransomware",
        "spyware", "attack", "hack", "crack", "breach", "vulnerability"
    ]
    value_lower = str(value).lower()
    for kw in keywords:
        if kw in value_lower:
            return True
    return False

def entropy(data):
    if isinstance(data, str):
        data = data.encode()
    if len(data) == 0:
        return 0
    probs = [float(data.count(i)) / len(data) for i in range(256)]
    return -sum([p * np.log2(p) for p in probs if p > 0])

def scan_dataframe(df, info):
    # Uniform scanning for object columns (text)
    for col in df.select_dtypes(include="object").columns:
        for idx, v in df[col].dropna().items():
            if detect_code_injection(v):
                info["security_findings"].append(f"Code/SQL injection pattern in '{col}', row {idx}: {v}")
            if detect_malicious_keywords(v):
                info["security_findings"].append(f"Malicious keyword in '{col}', row {idx}: {v}")
    # Numeric data poisoning detection
    for col in df.select_dtypes(include="number").columns:
        std = df[col].std()
        if std > 0:
            z = np.abs((df[col] - df[col].mean()) / std)
            if (z > 4).sum() >= 3:
                info["security_findings"].append(f"Possible data poisoning: extreme outliers in '{col}'")

def get_file_info(file_path):
    """Return dataset file info including type, size, hash, and advanced security metadata."""
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
        "details": {},
        "security_findings": []
    }

    try:
        # High entropy check
        with open(file_path, "rb") as f:
            file_entropy = entropy(f.read())
        if file_entropy > 7.5:
            info["security_findings"].append(f"High entropy ({file_entropy:.2f}) detected: possible malicious or steganographic data.")

        # CSV
        if ext == ".csv":
            info["type"] = "CSV file"
            df = pd.read_csv(file_path, nrows=100)
            info["details"] = {"columns": list(df.columns), "sample_rows": int(len(df))}
            scan_dataframe(df, info)

        # JSON
        elif ext == ".json":
            info["type"] = "JSON file"
            df = pd.read_json(file_path, lines=True, nrows=100)
            info["details"] = {"columns": list(df.columns), "sample_rows": int(len(df))}
            scan_dataframe(df, info)

        # Excel
        elif ext in [".xlsx", ".xls"]:
            info["type"] = "Excel file"
            df = pd.read_excel(file_path, nrows=100)
            info["details"] = {"columns": list(df.columns), "sample_rows": int(len(df))}
            scan_dataframe(df, info)

        # Parquet
        elif ext == ".parquet":
            info["type"] = "Parquet file"
            df = pd.read_parquet(file_path)
            info["details"] = {"columns": list(df.columns), "total_rows": int(len(df))}
            scan_dataframe(df, info)

        # ZIP
        elif ext == ".zip":
            info["type"] = "ZIP archive"
            with zipfile.ZipFile(file_path, 'r') as z:
                files_inside = []
                for fname in z.namelist():
                    entry = {"name": fname, "size": z.getinfo(fname).file_size}
                    # Try scanning file inside ZIP if it's a supported dataset
                    if fname.lower().endswith((".csv", ".json", ".xlsx", ".xls", ".parquet")):
                        with z.open(fname) as f:
                            try:
                                if fname.lower().endswith(".csv"):
                                    df = pd.read_csv(f, nrows=100)
                                elif fname.lower().endswith(".json"):
                                    df = pd.read_json(f, lines=True, nrows=100)
                                elif fname.lower().endswith((".xlsx", ".xls")):
                                    df = pd.read_excel(f, nrows=100)
                                elif fname.lower().endswith(".parquet"):
                                    df = pd.read_parquet(f)
                                scan_dataframe(df, info)
                                entry["columns"] = list(df.columns)
                            except Exception as scan_e:
                                info["security_findings"].append(f"Error scanning file '{fname}' in ZIP: {scan_e}")
                    files_inside.append(entry)
                info["details"]["files_inside"] = files_inside

        else:
            info["type"] = "Unknown/other file format"

    except Exception as e:
        info["security_findings"].append(f"Error scanning file: {str(e)}")
    return info

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python dataset_scanner.py <dataset_file>")
        sys.exit(1)
    path = sys.argv[1]
    try:
        report = get_file_info(path)
        print("\nDataset Security Scan Report")
        print("="*50)
        for k, v in report.items():
            if isinstance(v, list):
                for item in v:
                    print(f" - {item}")
            else:
                print(f"{k}: {v}")
    except Exception as e:
        print(f"Error: {e}")
