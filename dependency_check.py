import subprocess

def scan_dependencies():
    print("Running updated vulnerability scan with safety...")
    subprocess.run(["safety", "scan"])

if __name__ == "__main__":
    scan_dependencies()
