import os
import tempfile
import pandas as pd
import pytest
from src.dataset_scanner import get_file_info

@pytest.fixture
def temp_csv_factory():
    created_files = []
    def _create_temp_csv(data: dict):
        df = pd.DataFrame(data)
        path = tempfile.mktemp(suffix=".csv")
        df.to_csv(path, index=False)
        created_files.append(path)
        return path
    yield _create_temp_csv
    for path in created_files:
        if os.path.exists(path):
            os.remove(path)

def test_csv_file_info(temp_csv_factory):
    csv_path = temp_csv_factory({"col1": [1], "col2": ["a"]})
    info = get_file_info(csv_path)
    assert info["type"] == "CSV file"
    assert "columns" in info["details"]

def test_security_findings_injection(temp_csv_factory):
    data = {'comment': ["' OR 1=1; --"]}
    csv_path = temp_csv_factory(data)
    info = get_file_info(csv_path)
    findings = info.get("security_findings", [])
    assert any("Code/SQL injection pattern" in f for f in findings)

def test_data_poisoning_outliers(temp_csv_factory):
    data = {'sensor_reading': [10, 11, 10.5, 999, 1001, 998]}
    csv_path = temp_csv_factory(data)
    info = get_file_info(csv_path)
    findings = info.get("security_findings", [])
    assert any("Possible data poisoning" in f for f in findings)
