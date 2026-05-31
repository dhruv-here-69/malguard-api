import hashlib
import re


def calculate_sha256(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()


def extract_urls_from_text(text):

    pattern = r'https?://[^\s]+'

    return re.findall(pattern, text)
