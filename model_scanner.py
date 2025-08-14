import os
import hashlib

def calculate_sha256(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_file_info(file_path):
    if os.path.isdir(file_path):
        # For TensorFlow SavedModel (directory)
        size = sum(os.path.getsize(os.path.join(dirpath, filename))
                   for dirpath, _, files in os.walk(file_path)
                   for filename in files)
        info = {
            "type": "TensorFlow SavedModel directory",
            "size_bytes": size,
            "sha256": None  # Could extend to hash files inside but complex
        }
        return info
    elif os.path.isfile(file_path):
        ext = os.path.splitext(file_path)[1].lower()
        if ext in [".pt", ".pth"]:
            model_type = "PyTorch model file"
        elif ext == ".onnx":
            model_type = "ONNX model file"
        else:
            model_type = "Unknown model file type"


        size = os.path.getsize(file_path)
        sha256 = calculate_sha256(file_path)

        return {
            "type": model_type,
            "size_bytes": size,
            "sha256": sha256
        }
    else:
        raise FileNotFoundError(f"Path is neither file nor directory: {file_path}")

if __name__ == "__main__":
    model_path = r"C:\Kavi\Work\Models\resnet101-5d3b4d8f.pth"
    try:
        info = get_file_info(model_path)
        print(f"Model Info for '{model_path}':")
        for key, value in info.items():
            print(f"{key}: {value}")
    except Exception as e:
        print(f"Error: {e}")
