import subprocess
import json
import sys

def run_safety_scan():
    try:
        result = subprocess.run(
            ["safety", "scan", "--output", "json"],
            capture_output=True,
            text=True,
            check=True
        )
        # Print short output for debugging
        print("Raw safety scan output:", result.stdout[:500])
        # Parse JSON
        data = json.loads(result.stdout)
        print("\nDependency Security Scan Report")
        print("="*50)
        print("Scan metadata:", data.get("meta", {}))
        vulnerabilities = data.get("vulnerabilities", [])

        if vulnerabilities:
            print(f"Found {len(vulnerabilities)} vulnerabilities.")
            for v in vulnerabilities:
                print(f"Package: {v.get('package_name', '')} {v.get('package_version', '')}")
                print(f"Advisory: {v.get('advisory_id', '')} Severity: {v.get('severity', '')}")
                print(f"Description: {v.get('advisory_description', '')}\n")
        else:
            print("No vulnerabilities found.")
    except subprocess.CalledProcessError as e:
        print("Error during safety scan:", e)
    except json.JSONDecodeError as e:
        print("Could not parse JSON output:", e)
        print("Raw output was:", result.stdout)

def scan_installed_packages_for_typosquatting():
    import pkg_resources
    common_packages = {'numpy', 'pandas', 'requests', 'scipy', 'torch'}
    installed = [dist.project_name for dist in pkg_resources.working_set]
    typosquats = []
    for pkg in installed:
        for common in common_packages:
            # If a package name is similar to a common package but not exact, flag it (simple similarity)
            if pkg.lower() != common and pkg.lower().startswith(common):
                typosquats.append(pkg)
    if typosquats:
        print("Possible typosquatting/impersonation threats in installed packages:")
        for pkg in typosquats:
            print(f"  - {pkg}")
    else:
        print("No typosquatting patterns detected among installed packages.")

if __name__ == "__main__":
    run_safety_scan()
    print("\n--- Additional Checks ---")
    scan_installed_packages_for_typosquatting()
