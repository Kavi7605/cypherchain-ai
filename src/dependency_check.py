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
                    # Match package name, ignoring version specifiers
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
        data = json.loads(result.stdout)
        vulnerabilities = data.get("vulnerabilities", [])

        if vulnerabilities:
            report_lines.append(f"Found {len(vulnerabilities)} vulnerabilities:")
            for v in vulnerabilities:
                report_lines.append(f"\nPackage: {v.get('package_name', '')} == {v.get('vulnerable_spec', '')}")
                report_lines.append(f"  Affected Versions: {v.get('affected_versions', '')}")
                report_lines.append(f"  Advisory: {v.get('advisory_summary', '')}")
        else:
            report_lines.append("✅ No known security vulnerabilities found.")
        return "\n".join(report_lines)
    except FileNotFoundError:
        return "Error: 'safety' command not found. Please run 'pip install safety'."
    except json.JSONDecodeError:
        return f"Error: Could not parse scan results.\nRaw output:\n{result.stdout}"

def check_for_typosquatting(packages):
    """Checks a set of package names for common typosquatting patterns."""
    report_lines = ["\n--- Typosquatting & Impersonation Check ---"]
    common_packages = {'numpy', 'pandas', 'requests', 'scipy', 'torch', 'tensorflow', 'scikit-learn', 'matplotlib', 'pillow'}
    potential_typos = []

    for pkg_name in packages:
        for common in common_packages:
            if pkg_name != common and (common in pkg_name or pkg_name in common):
                potential_typos.append(f"'{pkg_name}' is very similar to the common package '{common}'. Please verify it is not a typosquatting attempt.")

    if potential_typos:
        report_lines.append("⚠️ Potential typosquatting threats found:")
        report_lines.extend([f"  - {p}" for p in potential_typos])
    else:
        report_lines.append("✅ No common typosquatting patterns detected.")
    return "\n".join(report_lines)

def scan_project_dependencies(project_path):
    """The main function to scan dependencies in a target project folder."""
    requirements_file = os.path.join(project_path, 'requirements.txt')

    if not os.path.exists(requirements_file):
        return f"Error: 'requirements.txt' not found in the selected folder:\n{project_path}"

    safety_report = run_safety_check(requirements_file)

    packages = parse_requirements(requirements_file)
    if packages is not None:
        typo_report = check_for_typosquatting(packages)
    else:
        typo_report = "Could not perform typosquatting check."

    return f"{safety_report}\n{typo_report}"

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python dependency_check.py <path_to_project_folder>")
        sys.exit(1)
    folder_path = sys.argv[1]
    print(scan_project_dependencies(folder_path))