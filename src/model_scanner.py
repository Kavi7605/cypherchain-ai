import os
import hashlib
import numpy as np

def calculate_sha256(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def entropy(data):
    """Shannon entropy estimate on bytes data."""
    if not data or len(data) == 0:
        return 0.0
    value_counts = np.array([data.count(byte) for byte in range(256)])
    probabilities = value_counts / len(data)
    entropy = -np.sum([p * np.log2(p) for p in probabilities if p > 0])
    return entropy

def scan_for_suspicious_patterns(file_path):
    """Detect common ML backdoor/malware indicators in binary."""
    patterns = [b'backdoor', b'trojan', b'trigger', b'exec', b'subprocess', b'eval(', b'importlib', b'pickle']
    hits = []
    with open(file_path, "rb") as f:
        data = f.read()
        for pat in patterns:
            if pat in data:
                hits.append(pat.decode(errors="ignore"))
    return hits

def get_file_info(file_path):
    if os.path.isdir(file_path):
        size = sum(os.path.getsize(os.path.join(dirpath, filename))
                   for dirpath, _, files in os.walk(file_path)
                   for filename in files)
        return {
            "type": "TensorFlow SavedModel directory",
            "size_bytes": size,
            "sha256": None,
            "mean_entropy": None,
            "suspicious_patterns": [],
            "notes": "Directory; scan individual files for threats."
        }
    elif os.path.isfile(file_path):
        ext = os.path.splitext(file_path)[1].lower()
        if ext in [".pt", ".pth"]:
            model_type = "PyTorch model file"
        elif ext == ".onnx":
            model_type = "ONNX model file"
        elif ext == ".pb":
            model_type = "TensorFlow protobuf file"
        elif ext == ".pkl":
            model_type = "Pickle model file (WARNING: code execution risk!)"
        else:
            model_type = "Unknown model file type"
        size = os.path.getsize(file_path)
        sha256 = calculate_sha256(file_path)
        # Entropy and suspicious bytes
        with open(file_path, "rb") as f:
            data = f.read(100*1024)  # Read first 100KB for speed
        mean_entropy = entropy(data)
        suspicious = scan_for_suspicious_patterns(file_path)
        notes = []
        if ext == ".pkl":
            notes.append("HIGH RISK: Pickle can execute arbitrary Python code! Only load from trusted sources.")
        if mean_entropy > 7.5:
            notes.append(f"High entropy ({mean_entropy:.2f}) detected: possible steganography or encrypted threat.")
        if suspicious:
            notes.append(f"Suspicious binary strings detected: {suspicious}")
        return {
            "type": model_type,
            "size_bytes": size,
            "sha256": sha256,
            "mean_entropy": mean_entropy,
            "suspicious_patterns": suspicious,
            "notes": notes,
        }
    else:
        raise FileNotFoundError(f"Path is neither file nor directory: {file_path}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python model_scanner.py <model-file-path>")
        sys.exit(1)
    model_path = sys.argv[1]
    try:
        info = get_file_info(model_path)
        print(f"\nModel Security Scan for '{model_path}'")
        print("="*50)
        for k, v in info.items():
            if isinstance(v, list):
                for item in v:
                    print(f"  - {item}")
            else:
                print(f"{k}: {v}")
    except Exception as e:
        print(f"Error: {e}")
