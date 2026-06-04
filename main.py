from fastapi import FastAPI, UploadFile, File, Form
from analyzer import (
    analyze_apk,
    analyze_exe,
    analyze_generic_file
)
from url_intel import analyze_url_safety

import tempfile
import os


app = FastAPI(title="MalGuard API")


@app.get("/")
def home():
    return {
        "status": "MalGuard Running"
    }


def analyze_by_extension(path: str, extension: str):
    if extension == ".apk":
        return analyze_apk(path)

    if extension == ".exe":
        return analyze_exe(path)

    return analyze_generic_file(path)


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

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=extension
        ) as temp:
            content = await file.read()
            temp.write(content)
            path = temp.name

        try:
            result = analyze_by_extension(path, extension)

            return {
                "status": "success",
                "source": "file",
                "filename": file.filename,
                "result": result
            }

        finally:
            if os.path.exists(path):
                os.remove(path)

    return {
        "status": "error",
        "message": "Provide either a file or a URL."
    }
