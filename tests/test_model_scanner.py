import os
import tempfile
import hashlib
import pytest
from src import model_scanner


def create_temp_file_with_content(content: bytes):
    """Helper function to create a temporary file with given bytes content."""
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file.write(content)
    temp_file.close()
    return temp_file.name

def test_calculate_sha256_known_value():
    # Create small temp file
    content = b"hello world"
    file_path = create_temp_file_with_content(content)

    # Expected SHA256 hash for "hello world"
    expected_hash = hashlib.sha256(content).hexdigest()

    # Run our function
    result_hash = model_scanner.calculate_sha256(file_path)

    # Verify hash value matches
    assert result_hash == expected_hash

    os.remove(file_path)  # Cleanup temp file

def test_get_file_info_pytorch_file():
    # Create dummy file with .pth extension
    file_path = create_temp_file_with_content(b"dummy model data")
    new_path = file_path + ".pth"
    os.rename(file_path, new_path)

    info = model_scanner.get_file_info(new_path)

    assert info["type"] == "PyTorch model file"
    assert info["size_bytes"] == os.path.getsize(new_path)
    assert len(info["sha256"]) == 64  # SHA-256 is always 64 hex chars

    os.remove(new_path)

def test_get_file_info_nonexistent_file():
    with pytest.raises(FileNotFoundError):
        model_scanner.get_file_info("non_existent_file.pth")
