import subprocess
import json

def run_safety_scan():
    try:
        result = subprocess.run(
            ["safety", "scan", "--output", "json"],
            capture_output=True,
            text=True,
            check=True
        )
        # Print output for debugging
        print("Raw safety scan output:", result.stdout[:500])

        # Parse JSON
        data = json.loads(result.stdout)

        # Work with JSON data keys
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

if __name__ == "__main__":
    run_safety_scan()
