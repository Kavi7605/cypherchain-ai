import os
import hashlib
import pandas as pd
import zipfile
import numpy as np
import re

def calculate_sha256(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(block)
    return sha256_hash.hexdigest()

def detect_code_injection(value):
    patterns = [
        r"(?i)\b(or|and)\b.+\b=\b", r"\b(drop\s+table)\b", r"\b(delete\s+from)\b",
        r"\b(insert\s+into)\b", r"\b(union\s+select)\b", r"eval\(", r"exec\(",
        r"system\(", r"base64,", r"<script>", r"alert\(", r"\.decode\(",
        r"import\s+os", r"os\.system\(", r";\s*--", r"#\s*--", r"admin' OR '1'='1"
    ]
    for pat in patterns:
        if re.search(pat, str(value), re.IGNORECASE):
            return True
    return False

def detect_malicious_keywords(value):
    keywords = [
        "exploit", "backdoor", "trojan", "virus", "malware", "keylogger",
        "rootkit", "botnet", "phishing", "ransomware", "spyware", "attack",
        "hack", "crack", "breach", "vulnerability"
    ]
    value_lower = str(value).lower()
    for kw in keywords:
        if kw in value_lower:
            return True
    return False

def entropy(data):
    if isinstance(data, str): data = data.encode()
    if len(data) == 0: return 0
    probs = [float(data.count(i)) / len(data) for i in range(256)]
    return -sum([p * np.log2(p) for p in probs if p > 0])

def scan_dataframe(df, info):
    for col in df.select_dtypes(include="object").columns:
        for idx, v in df[col].dropna().items():
            if detect_code_injection(v):
                info["security_findings"].append(f"Code/SQL injection pattern in '{col}', row {idx}: {v}")
            if detect_malicious_keywords(v):
                info["security_findings"].append(f"Malicious keyword in '{col}', row {idx}: {v}")

    for col in df.select_dtypes(include="number").columns:
        # **FIXED LOGIC**: Check for extreme spread, which is a strong indicator of poisoning.
        # A high standard deviation relative to the mean suggests a bimodal distribution.
        if not df[col].empty:
            std_dev = df[col].std()
            mean_val = df[col].mean()
            if std_dev > mean_val and mean_val != 0:
                info["security_findings"].append(f"Possible data poisoning: extreme outliers in '{col}'")

def get_file_info(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Path not found: {file_path}")
    size_bytes = os.path.getsize(file_path)
    checksum = calculate_sha256(file_path)
    ext = os.path.splitext(file_path)[1].lower()
    info = {
        "file_path": file_path, "size_bytes": size_bytes, "sha256": checksum,
        "type": None, "details": {}, "security_findings": []
    }
    try:
        with open(file_path, "rb") as f:
            file_entropy = entropy(f.read())
        if file_entropy > 7.5:
            info["security_findings"].append(f"High entropy ({file_entropy:.2f}) detected.")
        if ext == ".csv": info["type"] = "CSV file"; df = pd.read_csv(file_path, on_bad_lines='skip')
        elif ext == ".json": info["type"] = "JSON file"; df = pd.read_json(file_path, lines=True)
        elif ext in [".xlsx", ".xls"]: info["type"] = "Excel file"; df = pd.read_excel(file_path)
        elif ext == ".parquet": info["type"] = "Parquet file"; df = pd.read_parquet(file_path)
        elif ext == ".zip":
            info["type"] = "ZIP archive"
            with zipfile.ZipFile(file_path, 'r') as z:
                info["details"]["files_inside"] = [f.filename for f in z.infolist()]
            return info
        else:
            info["type"] = "Unknown/other file format"
            return info

        info["details"] = {"columns": list(df.columns), "rows": len(df)}
        scan_dataframe(df, info)
    except Exception as e:
        info["security_findings"].append(f"Error scanning file: {str(e)}")
    return info

