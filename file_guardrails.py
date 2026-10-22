"""
file_guardrails.py
------------------
File and attachment guardrails for SafeChat Gateway.
"The guard at the door now checks your bags too."

Provides checks for file type, file size, true signature (magic bytes),
PDF page limits, image EXIF metadata stripping, and text extraction.
Follows the exact same result structure as guardrails.py:
  {"name": ..., "status": "passed" | "blocked" | "modified", "message": ..., "data": ...}
"""

import io
from typing import Dict, Any, List, Optional, Tuple
import pypdf
import docx
from PIL import Image

# ============================================================================
# CONFIGURABLE CONSTANTS
# ============================================================================

# Permitted file extensions (case-insensitive)
ALLOWED_EXTENSIONS = {"pdf", "txt", "docx", "png", "jpg", "jpeg"}

# Maximum allowed file size in Megabytes (MB)
MAX_FILE_MB = 5

# Maximum allowed page count for PDF documents
MAX_PDF_PAGES = 10


# ============================================================================
# INDIVIDUAL FILE GUARDRAILS
# ============================================================================

def check_file_type(filename: str) -> Dict[str, Any]:
    """
    File Check 1: Allowed Extension
    Blocks uploads whose file extension is not in the approved safe list.
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if ext not in ALLOWED_EXTENSIONS:
        allowed_list = ", ".join(sorted(ALLOWED_EXTENSIONS))
        return {
            "name": "File Type Check",
            "status": "blocked",
            "message": f"File extension '.{ext or 'none'}' is not permitted. Allowed formats: {allowed_list}.",
            "data": filename,
            "text": filename,
        }

    return {
        "name": "File Type Check",
        "status": "passed",
        "message": f"File extension '.{ext}' is in the approved list.",
        "data": filename,
        "text": filename,
    }


def check_file_size(file_bytes: bytes, max_mb: int = MAX_FILE_MB) -> Dict[str, Any]:
    """
    File Check 2: File Size Limit
    Blocks uploads that exceed the maximum size threshold in megabytes.
    """
    size_mb = len(file_bytes) / (1024 * 1024)

    if size_mb > max_mb:
        return {
            "name": "File Size Limit",
            "status": "blocked",
            "message": f"File size ({size_mb:.2f} MB) exceeds the maximum limit of {max_mb} MB.",
            "data": file_bytes,
            "text": f"{size_mb:.2f} MB",
        }

    return {
        "name": "File Size Limit",
        "status": "passed",
        "message": f"File size ({size_mb:.2f} MB) is within the safe limit of {max_mb} MB.",
        "data": file_bytes,
        "text": f"{size_mb:.2f} MB",
    }


def check_real_type(filename: str, file_bytes: bytes) -> Dict[str, Any]:
    """
    File Check 3: True File Signature (Magic Bytes)
    Verifies that the raw header bytes match the declared file extension.
    Prevents executable files or scripts disguised with harmless extensions (e.g. .exe to .jpg).
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    is_valid = False
    details = ""

    if ext == "pdf":
        is_valid = file_bytes.startswith(b"%PDF")
        details = "Expected '%PDF' header."
    elif ext == "png":
        is_valid = file_bytes.startswith(b"\x89PNG")
        details = "Expected '\\x89PNG' header."
    elif ext in ("jpg", "jpeg"):
        is_valid = file_bytes.startswith(b"\xff\xd8")
        details = "Expected JPEG '\\xff\\xd8' SOI header."
    elif ext == "docx":
        # Microsoft Word .docx files are ZIP packages starting with PK
        is_valid = file_bytes.startswith(b"PK")
        details = "Expected ZIP 'PK' header for Office document."
    elif ext == "txt":
        # Plain text files must successfully decode as UTF-8
        try:
            file_bytes.decode("utf-8")
            is_valid = True
            details = "Valid UTF-8 encoded text."
        except UnicodeDecodeError:
            is_valid = False
            details = "File content failed UTF-8 text decoding."
    else:
        # If extension not mapped, treat as unverified
        is_valid = False
        details = f"Unknown file extension '.{ext}'."

    if not is_valid:
        return {
            "name": "Real Type Check",
            "status": "blocked",
            "message": f"File signature mismatch for '.{ext}': file header does not match declared type ({details}).",
            "data": file_bytes,
            "text": details,
        }

    return {
        "name": "Real Type Check",
        "status": "passed",
        "message": f"File header signature verified as genuine '.{ext}' format.",
        "data": file_bytes,
        "text": details,
    }


def check_page_limit(file_bytes: bytes, max_pages: int = MAX_PDF_PAGES) -> Dict[str, Any]:
    """
    File Check 4: PDF Page Count Limit
    For PDF documents only, blocks files exceeding the maximum page limit.
    """
    try:
        reader = pypdf.PdfReader(io.BytesIO(file_bytes))
        num_pages = len(reader.pages)

        if num_pages > max_pages:
            return {
                "name": "PDF Page Limit",
                "status": "blocked",
                "message": f"PDF has {num_pages} pages, which exceeds the allowed maximum of {max_pages} pages.",
                "data": file_bytes,
                "text": f"{num_pages} pages",
            }

        return {
            "name": "PDF Page Limit",
            "status": "passed",
            "message": f"PDF page count ({num_pages}) is within the safe limit of {max_pages} pages.",
            "data": file_bytes,
            "text": f"{num_pages} pages",
        }
    except Exception as e:
        return {
            "name": "PDF Page Limit",
            "status": "blocked",
            "message": f"Could not parse PDF to verify page limit: {str(e)}.",
            "data": file_bytes,
            "text": str(e),
        }


def strip_image_metadata(image_bytes: bytes) -> Dict[str, Any]:
    """
    File Check 5: Image Metadata Cleaner
    Re-saves images using Pillow without EXIF data to strip GPS coordinates,
    camera serials, and device information. Returns status 'modified' if EXIF
    was found and removed, otherwise 'passed'. Cleaned bytes returned in 'data'.
    """
    try:
        img = Image.open(io.BytesIO(image_bytes))
        exif = img.getexif()
        has_exif = bool(exif and len(exif) > 0) or bool(img.info.get("exif"))

        # Preserve the image format if possible (JPEG, PNG)
        raw_format = (img.format or "PNG").upper()
        if raw_format in ("JPG", "JPEG"):
            save_format = "JPEG"
        elif raw_format == "PNG":
            save_format = "PNG"
        else:
            save_format = raw_format

        # Re-save into clean buffer without EXIF metadata
        out = io.BytesIO()
        img.save(out, format=save_format)
        cleaned_bytes = out.getvalue()

        if has_exif:
            return {
                "name": "Metadata Cleaner",
                "status": "modified",
                "message": "EXIF metadata (such as GPS coordinates or camera info) was detected and stripped.",
                "data": cleaned_bytes,
                "text": "EXIF metadata stripped",
            }

        return {
            "name": "Metadata Cleaner",
            "status": "passed",
            "message": "No sensitive EXIF metadata detected in image.",
            "data": image_bytes,
            "text": "Clean image",
        }
    except Exception as e:
        # Fallback gracefully if Pillow cannot process
        return {
            "name": "Metadata Cleaner",
            "status": "passed",
            "message": f"Image metadata cleaner passed: {str(e)}.",
            "data": image_bytes,
            "text": str(e),
        }


# ============================================================================
# TEXT EXTRACTION
# ============================================================================

def extract_text(filename: str, file_bytes: bytes) -> Optional[str]:
    """
    Extracts plain text from PDF, DOCX, and TXT files.
    Returns None for image files (handled downstream by Gemini OCR/vision).
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    # Images do not have textual data extracted locally
    if ext in ("png", "jpg", "jpeg"):
        return None

    # TXT files: decode as UTF-8
    if ext == "txt":
        try:
            return file_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return file_bytes.decode("latin-1", errors="replace")

    # PDF documents: extract text page-by-page via pypdf
    if ext == "pdf":
        try:
            reader = pypdf.PdfReader(io.BytesIO(file_bytes))
            parts = []
            for page in reader.pages:
                txt = page.extract_text()
                if txt:
                    parts.append(txt)
            return "\n".join(parts).strip()
        except Exception:
            return ""

    # DOCX documents: extract paragraph text via python-docx
    if ext == "docx":
        try:
            doc = docx.Document(io.BytesIO(file_bytes))
            return "\n".join(p.text for p in doc.paragraphs if p.text).strip()
        except Exception:
            return ""

    return None


# ============================================================================
# PIPELINE RUNNER FOR FILE GUARDRAILS
# ============================================================================

def run_file_guardrails(
    filename: str,
    file_bytes: bytes,
    enabled_guardrails: Optional[Dict[str, bool]] = None
) -> Tuple[List[Dict[str, Any]], bytes]:
    """
    Runs file-level guardrails in sequential order:
      1. check_file_type (Extension check)
      2. check_file_size (Size limit)
      3. check_real_type (Signature/magic bytes)
      4. check_page_limit (PDFs only)
      5. strip_image_metadata (Images only)

    Skips any guardrails disabled in `enabled_guardrails`.
    Stops immediately at the first 'blocked' result.
    Returns: (list_of_results, cleaned_file_bytes).
    """
    if enabled_guardrails is None:
        enabled_guardrails = {}

    results: List[Dict[str, Any]] = []
    current_bytes = file_bytes
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    # 1. File Type Check
    if enabled_guardrails.get("File Type Check", True):
        res = check_file_type(filename)
        results.append(res)
        if res["status"] == "blocked":
            return results, current_bytes

    # 2. File Size Limit
    if enabled_guardrails.get("File Size Limit", True):
        res = check_file_size(current_bytes)
        results.append(res)
        if res["status"] == "blocked":
            return results, current_bytes

    # 3. Real Type Check (Magic Bytes)
    if enabled_guardrails.get("Real Type Check", True):
        res = check_real_type(filename, current_bytes)
        results.append(res)
        if res["status"] == "blocked":
            return results, current_bytes

    # 4. PDF Page Limit (PDF documents only)
    if ext == "pdf" and enabled_guardrails.get("PDF Page Limit", True):
        res = check_page_limit(current_bytes)
        results.append(res)
        if res["status"] == "blocked":
            return results, current_bytes

    # 5. Image Metadata Cleaner (Images only)
    if ext in ("png", "jpg", "jpeg") and enabled_guardrails.get("Metadata Cleaner", True):
        res = strip_image_metadata(current_bytes)
        results.append(res)
        if res["status"] == "modified":
            current_bytes = res["data"]
        if res["status"] == "blocked":
            return results, current_bytes

    return results, current_bytes
