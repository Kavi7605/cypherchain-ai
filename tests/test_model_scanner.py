import os
import tempfile
import hashlib
import pytest
from src import model_scanner

def create_temp_file_with_content(content: bytes):
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file.write(content)
    temp_file.close()
    return temp_file.name

def test_calculate_sha256_known_value():
    content = b"hello world"
    file_path = create_temp_file_with_content(content)
    expected_hash = hashlib.sha256(content).hexdigest()
    result_hash = model_scanner.calculate_sha256(file_path)
    assert result_hash == expected_hash
    os.remove(file_path)

def test_get_file_info_pytorch_file():
    file_path = create_temp_file_with_content(b"dummy model data")
    new_path = file_path + ".pth"
    os.rename(file_path, new_path)
    info = model_scanner.get_file_info(new_path)
    assert info["type"] == "PyTorch model file"
    assert info["size_bytes"] == os.path.getsize(new_path)
    assert len(info["sha256"]) == 64
    os.remove(new_path)

def test_get_file_info_nonexistent_file():
    with pytest.raises(FileNotFoundError):
        model_scanner.get_file_info("non_existent_file.pth")

def test_suspicious_pattern_detection():
    suspicious_content = b"backdoor\x00trojan\x00trigger\x00eval(\x00subprocess"
    file_path = create_temp_file_with_content(suspicious_content)
    new_path = file_path + ".pth"
    os.rename(file_path, new_path)
    info = model_scanner.get_file_info(new_path)
    assert any(pattern in info["suspicious_patterns"] for pattern in ['backdoor', 'trojan'])
    os.remove(new_path)

def test_entropy_detection():
    # create high entropy content (random bytes)
    import os
    content = os.urandom(10000)
    file_path = create_temp_file_with_content(content)
    info = model_scanner.get_file_info(file_path)
    assert info["mean_entropy"] > 7.0
    os.remove(file_path)
