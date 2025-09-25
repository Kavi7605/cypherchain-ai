import subprocess
import json
import os
import re

def parse_requirements(file_path):
    """Parses package names from a requirements.txt file."""
    packages = set()
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    match = re.match(r"^[a-zA-Z0-9\-_]+", line)
                    if match:
                        packages.add(match.group(0).lower())
    except FileNotFoundError:
        return None
    return packages

def run_safety_check(requirements_path):
    """Runs 'safety check' on a given requirements.txt file."""
    report_lines = ["--- Dependency Vulnerability Report (safety) ---"]
    try:
        result = subprocess.run(
            ["safety", "check", "-r", requirements_path, "--json"],
            capture_output=True, text=True
        )
        if not result.stdout.strip():
            report_lines.append("✅ No known security vulnerabilities found.")
            return "\n".join(report_lines)

        data = json.loads(result.stdout)
        vulnerabilities = data.get("vulnerabilities", [])
        if vulnerabilities:
            report_lines.append(f"Found {len(vulnerabilities)} vulnerabilities:")
            for v in vulnerabilities:
                report_lines.append(f"\nPackage: {v.get('package_name', '')} == {v.get('vulnerable_spec', '')}")
                report_lines.append(f"  Advisory: {v.get('advisory_summary', '')}")
        else:
            report_lines.append("✅ No known security vulnerabilities found.")
    except FileNotFoundError:
        return "Error: 'safety' command not found. Please run 'pip install safety'."
    except json.JSONDecodeError:
        report_lines.append("✅ No known security vulnerabilities found (non-JSON response from 'safety').")
    except Exception as e:
        return f"An unexpected error occurred during safety scan: {e}"
    return "\n".join(report_lines)

def check_for_typosquatting(packages):
    """Checks a set of package names for common typosquatting patterns."""
    report_lines = ["\n--- Typosquatting & Impersonation Check ---"]
    common_packages = {'numpy', 'pandas', 'requests', 'scipy', 'torch', 'tensorflow', 'scikit-learn'}
    potential_typos = []
    for pkg_name in packages:
        for common in common_packages:
            if pkg_name != common and (common in pkg_name or pkg_name in common):
                potential_typos.append(f"'{pkg_name}' is similar to '{common}'. Please verify it is not a typosquatting attempt.")
    if potential_typos:
        report_lines.append("⚠️ Potential typosquatting threats found:")
        report_lines.extend([f"  - {p}" for p in potential_typos])
    else:
        report_lines.append("✅ No common typosquatting patterns detected.")
    return "\n".join(report_lines)

def scan_dependency_file(requirements_path):
    """The main function to scan a specific requirements.txt file."""
    if not os.path.exists(requirements_path):
        return f"Error: File not found:\n{requirements_path}"

    safety_report = run_safety_check(requirements_path)
    packages = parse_requirements(requirements_path)
    typo_report = check_for_typosquatting(packages) if packages else ""
    return f"{safety_report}\n{typo_report}"

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python dependency_check.py <path_to_requirements.txt>")
        sys.exit(1)
    file_path = sys.argv[1]
    print(scan_dependency_file(file_path))

