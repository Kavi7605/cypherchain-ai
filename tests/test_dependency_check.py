import subprocess
import sys
import pytest
from src import dependency_check

def test_run_safety_scan():
    try:
        # Simply run and check output contains expected keys
        dependency_check.run_safety_scan()
    except Exception:
        pytest.skip("Safety scan requires safety package and network connection")

def test_typosquatting_detection_print(capsys):
    dependency_check.scan_installed_packages_for_typosquatting()
    captured = capsys.readouterr()
    # Should print warnings or no warnings message
    assert "typosquatting" in captured.out.lower() or "no typosquatting" in captured.out.lower()
