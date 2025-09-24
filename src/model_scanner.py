import os
import hashlib
import numpy as np
import json
import hashlib
import os

# A unique sequence of bytes to identify the start of our watermark block
# This MUST be identical to the one in tools/watermarker.py
WATERMARK_MAGIC = b"##CYPHERCHAIN_WM##"

def verify_watermark(file_path: str):
    """
    Checks for and verifies the embedded watermark in a file.

    Returns:
        A dictionary with verification status and data, or None if no watermark is found.
    """
    try:
        with open(file_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            file_size = f.tell()

            # Read the last few KB to search for the magic number for efficiency
            scan_size = min(file_size, 4096)
            if scan_size == 0:
                return None

            f.seek(file_size - scan_size, os.SEEK_SET)
            end_data = f.read()

            # Use rfind to get the last occurrence, in case of accidental inclusion
            magic_pos = end_data.rfind(WATERMARK_MAGIC)

            if magic_pos == -1:
                return None # No watermark found

            # We found the magic number, now let's parse the block
            watermark_block_start_in_file = file_size - scan_size + magic_pos
            json_str = end_data[magic_pos + len(WATERMARK_MAGIC):].decode('utf-8')

            watermark_data = json.loads(json_str)

            # Separate the original file content from the watermark block
            f.seek(0, os.SEEK_SET)
            original_content = f.read(watermark_block_start_in_file)

            # Recalculate the integrity hash to verify
            stored_hash = watermark_data.pop('integrity_hash', None)

            # The integrity hash was calculated on the original content + metadata *without* the hash itself
            recalculated_json_str = json.dumps(watermark_data, separators=(",", ":"))
            expected_hash = hashlib.sha256(original_content + recalculated_json_str.encode('utf-8')).hexdigest()

            if expected_hash == stored_hash:
                watermark_data['status'] = 'VALID'
            else:
                watermark_data['status'] = 'TAMPERED'

            return watermark_data

    except (json.JSONDecodeError, FileNotFoundError, KeyError):
        # This can happen if the file is corrupt or the watermark is malformed
        return {"status": "INVALID_FORMAT"}
    except Exception:
        return {"status": "VERIFICATION_ERROR"}

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
        with open(file_path, "rb") as f:
            data = f.read(100*1024)
        mean_entropy = entropy(data)
        suspicious = scan_for_suspicious_patterns(file_path)

        # --- START: WATERMARK INTEGRATION ---
        actionable_insights = [
            "Consider validating the model's integrity (e.g., with a trusted file hash).",
            "Manually inspect for trojans or backdoors if patterns match sensitive keywords."
        ]

        watermark_info = verify_watermark(file_path)
        watermark_report_data = None # Initialize variable for the final report

        if watermark_info:
            status = watermark_info.get('status')
            watermark_report_data = watermark_info # Store full data for the report

            if status == 'VALID':
                author = watermark_info.get('author', 'N/A')
                # Prepend to make it the first insight
                actionable_insights.insert(0, f"✅ SUCCESS: Valid watermark found. Author: {author}")
            elif status == 'TAMPERED':
                actionable_insights.insert(0, "🚨 CRITICAL ALERT: Watermark found, but file has been TAMPERED with!")
            else:
                actionable_insights.insert(0, "⚠️ WARNING: Malformed watermark block found.")
        # --- END: WATERMARK INTEGRATION ---

        notes = {
            "File Type": model_type,
            "Entropy": f"{mean_entropy:.2f} (High risk if >7.5)",
            "Pattern Matches": suspicious,
            "Actionable Insights": actionable_insights, # Use the updated list
        }

        return {
            "type": model_type,
            "size_bytes": size,
            "sha256": sha256,
            "mean_entropy": mean_entropy,
            "suspicious_patterns": suspicious,
            "notes": notes,
            "watermark": watermark_report_data # Add watermark data to the final report
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
