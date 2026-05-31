from fastapi import FastAPI, UploadFile, File
from analyzer import (
    analyze_apk,
    analyze_exe,
    analyze_generic_file
)

import tempfile
import os

app = FastAPI(title="MalGuard API")


@app.get("/")
def home():
    return {
        "status": "MalGuard Running"
    }


@app.post("/scan")
async def scan(file: UploadFile = File(...)):

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

        result["filename"] = file.filename

        return result

    finally:

        if os.path.exists(path):
            os.remove(path)
