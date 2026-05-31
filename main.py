from fastapi import FastAPI, UploadFile, File
import os
import tempfile

app = FastAPI(title="MalGuard API")


@app.get("/")
def home():
    return {
        "status": "MalGuard API Running"
    }


@app.post("/scan")
async def scan(file: UploadFile = File(...)):

    filename = file.filename
    extension = os.path.splitext(filename)[1].lower()

    with tempfile.NamedTemporaryFile(delete=False, suffix=extension) as temp_file:
        contents = await file.read()
        temp_file.write(contents)
        temp_path = temp_file.name

    result = {
        "filename": filename,
        "file_type": extension,
        "file_size_bytes": len(contents),
        "status": "received"
    }

    return result
