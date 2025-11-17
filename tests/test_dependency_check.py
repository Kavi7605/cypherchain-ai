import os
import pytest
from src.dependency_check import scan_dependency_file

@pytest.fixture
def project_dir(tmp_path):
    d = tmp_path / "project"
    d.mkdir()
    return d

def test_scan_clean_dependencies(project_dir):
    (project_dir / "requirements.txt").write_text("pandas==2.2.0\nnumpy==1.26.4")
    # This test will call the real 'safety' command, which should pass for recent versions
    report = scan_dependency_file(str(project_dir / "requirements.txt"))
    assert "No known security vulnerabilities found" in report
    assert "No common typosquatting patterns detected" in report

def test_scan_vulnerable_dependencies(project_dir, monkeypatch):
    (project_dir / "requirements.txt").write_text("requests==2.19.0")

    # We mock the subprocess call to avoid depending on network and safety db
    # and to ensure the test is reliable.
    class MockCompletedProcess:
        stdout = '{"vulnerabilities": [{"package_name": "requests", "advisory_summary": "Test Vuln"}]}'
        stderr = ''

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: MockCompletedProcess())

    report = scan_dependency_file(str(project_dir / "requirements.txt"))
    assert "Found 1 vulnerabilities" in report
    assert "Test Vuln" in report

def test_scan_typosquatting(project_dir):
    (project_dir / "requirements.txt").write_text("tensorflow-gpu\nnumpy-utils")
    report = scan_dependency_file(str(project_dir / "requirements.txt"))
    assert "Potential typosquatting threats found" in report
    assert "'tensorflow-gpu'" in report
    assert "'numpy-utils'" in report

def test_no_requirements_file(project_dir):
    report = scan_dependency_file(str(project_dir / "requirements.txt"))
    assert "Error: 'requirements.txt' not found" in report
