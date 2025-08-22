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
        r"<script.*?>.*?</script>", r"eval\(", r"exec\(", r"system\(", r"base64,",
        r"drop\s+table", r"delete\s+from", r"insert\s+into", r"union\s+select",
    ]
    for pat in patterns:
        if re.search(pat, str(value), re.IGNORECASE):
            return True
    return False

def detect_malicious_keywords(value):
    keywords = [
        "exploit", "backdoor", "trojan", "virus", "malware", "keylogger", "rootkit", "botnet",
        "phishing", "ransomware", "spyware", "attack", "hack", "crack", "breach", "vulnerability"
    ]
    for kw in keywords:
        if kw in str(value).lower():
            return True
    return False

def entropy(data):
    data = bytes(data)
    if len(data) == 0:
        return 0
    probs = [float(data.count(i)) / len(data) for i in range(256)]
    return -sum([p * np.log2(p) for p in probs if p > 0])

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
        # High entropy check (hidden payloads/steganography)
        with open(file_path, "rb") as f:
            file_entropy = entropy(f.read())
        if file_entropy > 7.5:
            info["security_findings"].append(f"High entropy ({file_entropy:.2f}) detected: possible malicious/steganographic data.")

        if ext == ".csv":
            info["type"] = "CSV file"
            df = pd.read_csv(file_path, nrows=100) # read first 100 rows
            info["details"] = {"columns": list(df.columns), "sample_rows": int(len(df))}
            # Scan for injection/malware
            for col in df.select_dtypes(include="object").columns:
                for idx, v in df[col].dropna().items():
                    if detect_code_injection(v):
                        info["security_findings"].append(f"Code/SQL injection pattern in column '{col}', row {idx}")
                    if detect_malicious_keywords(v):
                        info["security_findings"].append(f"Malicious keyword in column '{col}', row {idx}")
            # Data poisoning (extreme outliers)
            for col in df.select_dtypes(include="number").columns:
                std = df[col].std()
                if std > 0:
                    z = np.abs((df[col] - df[col].mean()) / std)
                    if (z > 4).sum() > 3:
                        info["security_findings"].append(f"Possible poisoning: extreme outliers in numeric column '{col}'")
        elif ext == ".json":
            info["type"] = "JSON file"
            df = pd.read_json(file_path, lines=True, nrows=100)
            info["details"] = {"columns": list(df.columns), "sample_rows": int(len(df))}
            for col in df.select_dtypes(include="object").columns:
                for idx, v in df[col].dropna().items():
                    if detect_code_injection(v):
                        info["security_findings"].append(f"Code/SQL injection pattern in column '{col}', row {idx}")
                    if detect_malicious_keywords(v):
                        info["security_findings"].append(f"Malicious keyword in column '{col}', row {idx}")
        elif ext in [".xlsx", ".xls"]:
            info["type"] = "Excel file"
            df = pd.read_excel(file_path, nrows=100)
            info["details"] = {"columns": list(df.columns), "sample_rows": int(len(df))}
        elif ext == ".parquet":
            info["type"] = "Parquet file"
            df = pd.read_parquet(file_path)
            info["details"] = {"columns": list(df.columns), "total_rows": int(len(df))}
        elif ext == ".zip":
            info["type"] = "ZIP archive"
            with zipfile.ZipFile(file_path, 'r') as z:
                info["details"]["files_inside"] = [
                    {"name": f, "size": z.getinfo(f).file_size} for f in z.namelist()
                ]
        else:
            info["type"] = "Unknown/other file format"
    except Exception as e:
        info["security_findings"].append(f"Error scanning file: {str(e)}")
    return info

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python dataset_scanner.py <dataset-file>")
        sys.exit(1)
    path = sys.argv[1]
    try:
        report = get_file_info(path)
        print("\nDataset Security Scan Report")
        print("="*50)
        for k, v in report.items():
            if isinstance(v, list):
                for item in v:
                    print(f"  - {item}")
            else:
                print(f"{k}: {v}")
    except Exception as e:
        print(f"Error: {e}")
