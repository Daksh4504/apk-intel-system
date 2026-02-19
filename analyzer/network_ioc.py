import re

URL_REGEX = re.compile(
    r'(https?://[^\s"\'>]+)',
    re.IGNORECASE
)

IP_REGEX = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)

def extract_iocs_from_file(file_path):
    urls = set()
    ips = set()

    try:
        with open(file_path, "rb") as f:
            content = f.read().decode(errors="ignore")

            urls.update(URL_REGEX.findall(content))
            ips.update(IP_REGEX.findall(content))

    except Exception:
        pass

    return {
        "urls": list(urls),
        "ips": list(ips)
    }
