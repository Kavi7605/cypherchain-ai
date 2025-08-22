import sys
import os
import tempfile
import zipfile
import pandas as pd
import pytest
from src import dataset_scanner
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

def create_temp_csv(data=None):
    df = pd.DataFrame(data or {"a": [1, 2], "b": [3, 4]})
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
    df.to_csv(temp_file.name, index=False)
    return temp_file.name

def test_calculate_sha256_known_content():
    file_path = tempfile.NamedTemporaryFile(delete=False)
    content = b"dataset content"
    file_path.write(content)
    file_path.flush()
    file_path.close()
    expected = dataset_scanner.hashlib.sha256(content).hexdigest()
    assert dataset_scanner.calculate_sha256(file_path.name) == expected
    os.remove(file_path.name)

def test_csv_file_info():
    csv_path = create_temp_csv()
    info = dataset_scanner.get_file_info(csv_path)
    assert info["type"] == "CSV file"
    assert "columns" in info["details"]
    assert "sample_rows" in info["details"]
    os.remove(csv_path)

def test_zip_file_info():
    temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    with zipfile.ZipFile(temp_zip.name, 'w') as z:
        z.writestr("file1.txt", "hello zip")
    temp_zip.close()
    info = dataset_scanner.get_file_info(temp_zip.name)
    assert info["type"] == "ZIP archive"
    assert "files_inside" in info["details"]
    os.remove(temp_zip.name)

def test_nonexistent_file():
    with pytest.raises(FileNotFoundError):
        dataset_scanner.get_file_info("no_such_file.csv")

def test_security_findings_injection():
    data = {
        'user': ['normal', "'; DROP TABLE users; --", "admin' OR '1'='1"],
        'comment': ['safe', '<script>alert(1)</script>', 'normal'],
    }
    csv_path = create_temp_csv(data)
    info = dataset_scanner.get_file_info(csv_path)
    findings = info.get("security_findings", [])
    assert any("Code/SQL injection pattern" in f for f in findings)
    assert any("Malicious keyword" in f for f in findings)
    os.remove(csv_path)
