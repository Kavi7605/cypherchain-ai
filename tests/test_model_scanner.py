import os
import tempfile
import hashlib
import pytest
import subprocess
import sys
from src.model_scanner import get_file_info, verify_watermark

@pytest.fixture
def temp_file_factory():
    created_files = []
    def _create_temp_file(content: bytes, suffix=""):
        path = tempfile.mktemp(suffix=suffix)
        with open(path, "wb") as f:
            f.write(content)
        created_files.append(path)
        return path
    yield _create_temp_file
    for path in created_files:
        if os.path.exists(path):
            os.remove(path)

def test_get_file_info_pytorch_file(temp_file_factory):
    file_path = temp_file_factory(b"dummy model data", suffix=".pth")
    info = get_file_info(file_path)
    assert info["type"] == "PyTorch model file"
    assert info["size_bytes"] > 0

def test_suspicious_pattern_detection(temp_file_factory):
    content = b"some data then backdoor then other data"
    file_path = temp_file_factory(content, suffix=".pth")
    info = get_file_info(file_path)
    assert "backdoor" in info["suspicious_patterns"]

def test_watermark_verification_and_tampering(temp_file_factory):
    original_content = b"This is a secure model."
    model_path = temp_file_factory(original_content)

    watermarker_script = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tools', 'watermarker.py'))

    # 1. Embed a valid watermark
    subprocess.run(
        [sys.executable, watermarker_script, model_path, "--author", "Test Author", "--project", "Test Project"],
        check=True
    )

    # 2. Verify the valid watermark
    watermark_data = verify_watermark(model_path)
    assert watermark_data is not None
    assert watermark_data['status'] == 'VALID'
    assert watermark_data['author'] == 'Test Author'

    # 3. Tamper with the file
    with open(model_path, "ab") as f:
        f.write(b"tampered")

    # 4. Verify the tampered watermark
    tampered_data = verify_watermark(model_path)
    assert tampered_data is not None
    assert tampered_data['status'] == 'TAMPERED'

def test_nonexistent_file():
    with pytest.raises(FileNotFoundError):
        get_file_info("non_existent_file.pth")
