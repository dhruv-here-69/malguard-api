from fastapi import FastAPI, UploadFile, File, Form
from analyzer import (
    analyze_apk,
    analyze_exe,
    analyze_generic_file
)

import tempfile
import requests
import os

app = FastAPI(title="MalGuard API")


@app.get("/")
def home():
    return {
        "status": "MalGuard Running"
    }


@app.post("/scan")
async def scan(
    file: UploadFile = File(None),
    url: str = Form(None)
):

    # ==========================
    # URL ANALYSIS
    # ==========================
    if url:

        try:

            response = requests.get(
                url,
                timeout=30,
                allow_redirects=True
            )

            response.raise_for_status()

            extension = os.path.splitext(
                url.split("?")[0]
            )[1].lower()

            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=extension
            ) as temp:

                temp.write(response.content)
                path = temp.name

            try:

                if extension == ".apk":

                    result = analyze_apk(path)

                elif extension == ".exe":

                    result = analyze_exe(path)

                else:

                    result = analyze_generic_file(path)

                return {
                    "status": "success",
                    "source": "url",
                    "url": url,
                    "result": result
                }

            finally:

                if os.path.exists(path):
                    os.remove(path)

        except Exception as e:

            return {
                "status": "error",
                "source": "url",
                "url": url,
                "error": str(e)
            }

    # ==========================
    # FILE ANALYSIS
    # ==========================
    if file:

        extension = os.path.splitext(
            file.filename
        )[1].lower()

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=extension
        ) as temp:

            content = await file.read()

            temp.write(content)

            path = temp.name

        try:

            if extension == ".apk":

                result = analyze_apk(path)

            elif extension == ".exe":

                result = analyze_exe(path)

            else:

                result = analyze_generic_file(path)

            return {
                "status": "success",
                "source": "file",
                "filename": file.filename,
                "result": result
            }

        finally:

            if os.path.exists(path):
                os.remove(path)

    # ==========================
    # NO INPUT PROVIDED
    # ==========================
    return {
        "status": "error",
        "message": "Provide either a file or a URL."
    }
