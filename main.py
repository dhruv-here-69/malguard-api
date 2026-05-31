from fastapi import FastAPI, UploadFile, File
from analyzer import analyze_apk, analyze_exe

import tempfile
import os

app = FastAPI(title="MalGuard API")


@app.get("/")
def home():
    return {"status": "MalGuard Running"}


@app.post("/scan")
async def scan(file: UploadFile = File(...)):

    extension = os.path.splitext(file.filename)[1].lower()

    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=extension
    ) as temp:

        content = await file.read()

        temp.write(content)

        path = temp.name

    if extension == ".apk":

        return analyze_apk(path)

    elif extension == ".exe":

        return analyze_exe(path)

    return {
        "error": "Unsupported file type"
    }
