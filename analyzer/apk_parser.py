import hashlib
import os
from datetime import datetime

def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()

def get_file_size(file_path):
    size_bytes = os.path.getsize(file_path)
    size_mb = round(size_bytes / (1024 * 1024), 2)
    return f"{size_mb} MB"

def extract_basic_info(file_path):
    return {
        "sha256": calculate_sha256(file_path),
        "file_size": get_file_size(file_path),
        "analysis_time": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        "file_path": file_path
    }
