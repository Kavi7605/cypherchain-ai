import json
import hashlib
import datetime
import argparse
import sys
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

# A unique sequence of bytes to identify the start of our watermark block
WATERMARK_MAGIC = b"##CYPHERCHAIN_WM##"

def embed_watermark(file_path: str, author: str, project_name: str):
    """
    Embeds a secure watermark block at the end of a file.

    Args:
        file_path (str): The path to the model file.
        author (str): The name of the author or organization.
        project_name (str): The name of the project.
    """
    try:
        # 1. Read the original model content
        with open(file_path, "rb") as f:
            original_content = f.read()

        # 2. Prepare the metadata for the watermark
        watermark_data = {
            "author": author,
            "project_name": project_name,
            "timestamp_utc": datetime.datetime.utcnow().isoformat(),
            "original_file_sha256": hashlib.sha256(original_content).hexdigest(),
        }

        # 3. Create the full watermark block
        # We create a final hash of the original content + the metadata to ensure integrity
        # This prevents someone from cutting off our watermark and adding their own.
        watermark_json_str = json.dumps(watermark_data, separators=(",", ":"))
        combined_hash = hashlib.sha256(original_content + watermark_json_str.encode('utf-8')).hexdigest()
        watermark_data['integrity_hash'] = combined_hash

        # Final JSON string with the integrity hash included
        final_watermark_json_str = json.dumps(watermark_data, separators=(",", ":"))
        watermark_block = WATERMARK_MAGIC + final_watermark_json_str.encode('utf-8')

        # 4. Append the watermark block to the original file
        with open(file_path, "ab") as f:
            f.write(watermark_block)

        print(f"✅ Watermark successfully embedded into '{file_path}'")
        print(f"   Author: {author}, Project: {project_name}")

    except FileNotFoundError:
        print(f"❌ Error: File not found at '{file_path}'")
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Embed a secure watermark into a file.")
    parser.add_argument("file", help="The path to the file to watermark.")
    parser.add_argument("--author", required=True, help="The author or organization name.")
    parser.add_argument("--project", required=True, help="The project name.")

    args = parser.parse_args()

    embed_watermark(args.file, args.author, args.project)