import os
import tempfile
import asyncio

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Any, Dict

from analyzer import (
    analyze_apk,
    analyze_exe,
    analyze_generic_file
)

from url_intel import analyze_url_safety
from pdf_generator import generate_pdf_report


app = FastAPI(title="MalGuard API")


MAX_UPLOAD_SIZE = 75 * 1024 * 1024  # 75 MB
APK_DEEP_ANALYSIS_LIMIT = 25 * 1024 * 1024  # 25 MB
ANALYSIS_TIMEOUT_SECONDS = 180


class ReportRequest(BaseModel):
    report: Dict[str, Any]


@app.get("/")
def home():
    return {
        "status": "MalGuard Running"
    }


def analyze_by_extension(path: str, extension: str, file_size: int):
    if extension == ".apk":

        if file_size > APK_DEEP_ANALYSIS_LIMIT:
            result = analyze_generic_file(path)

            result["file_type"] = "apk"
            result["analysis_mode"] = "large_apk_limited_analysis"
            result["note"] = (
                "Large APK detected. Full Androguard APK analysis was skipped "
                "to prevent cloud timeout. SHA256, YARA, URL extraction and "
                "sandbox heuristic analysis were performed."
            )

            return result

        return analyze_apk(path)

    if extension == ".exe":
        return analyze_exe(path)

    return analyze_generic_file(path)


async def run_analysis_with_timeout(path: str, extension: str, file_size: int):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(
                analyze_by_extension,
                path,
                extension,
                file_size
            ),
            timeout=ANALYSIS_TIMEOUT_SECONDS
        )

    except asyncio.TimeoutError:
        fallback = analyze_generic_file(path)

        fallback["analysis_mode"] = "timeout_fallback_analysis"
        fallback["note"] = (
            "Deep analysis timed out in the cloud environment. "
            "Fallback static analysis was completed using SHA256, YARA, "
            "URL extraction and sandbox heuristics."
        )

        return fallback


@app.post("/scan")
async def scan(
    file: UploadFile = File(None),
    url: str = Form(None)
):

    if url:
        result = analyze_url_safety(url)

        return {
            "status": "success",
            "source": "url",
            "filename": result.get("url"),
            "submitted_url": result.get("url"),
            "result": result
        }

    if file:
        extension = os.path.splitext(file.filename)[1].lower()

        if not extension:
            extension = ".bin"

        content = await file.read()
        file_size = len(content)

        if file_size > MAX_UPLOAD_SIZE:
            return {
                "status": "error",
                "source": "file",
                "filename": file.filename,
                "message": "File too large for current cloud limit.",
                "max_size_mb": int(MAX_UPLOAD_SIZE / 1024 / 1024),
                "uploaded_size_mb": round(file_size / 1024 / 1024, 2)
            }

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=extension
        ) as temp:
            temp.write(content)
            path = temp.name

        try:
            result = await run_analysis_with_timeout(
                path,
                extension,
                file_size
            )

            return {
                "status": "success",
                "source": "file",
                "filename": file.filename,
                "file_size_bytes": file_size,
                "result": result
            }

        except Exception as e:
            return {
                "status": "error",
                "source": "file",
                "filename": file.filename,
                "error": str(e)
            }

        finally:
            if os.path.exists(path):
                os.remove(path)

    return {
        "status": "error",
        "message": "Provide either a file or a URL."
    }


@app.post("/generate-report")
async def generate_report(request: ReportRequest):

    pdf_path = generate_pdf_report(
        request.report
    )

    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename="malguard_report.pdf"
    )
