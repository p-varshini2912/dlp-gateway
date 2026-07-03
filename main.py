# main.py
# FastAPI gateway - takes a text file upload, runs it through scanner.py,
# hands back the redacted version + some stats.

from typing import Dict, Any

from fastapi import FastAPI, UploadFile, File
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from scanner import scanner, ScanError

app = FastAPI(title="DLP Gateway")
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def serve_ui():
    return FileResponse("static/index.html")

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    name = file.filename or "unnamed_file"

    try:
        raw = await file.read()
    except Exception as e:
        return JSONResponse(status_code=400, content={
            "filename": name,
            "status": "failed",
            "error": f"couldn't read the upload: {e}",
        })

    if not raw:
        return JSONResponse(status_code=400, content={
            "filename": name,
            "status": "failed",
            "error": "file is empty",
        })

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        return JSONResponse(status_code=400, content={
            "filename": name,
            "status": "failed",
            "error": f"file isn't valid utf-8, can't scan it: {e}",
        })

    try:
        result: Dict[str, Any] = scanner.scan(text)
    except ScanError as e:
        return JSONResponse(status_code=422, content={
            "filename": name,
            "status": "scan_failed",
            "error": str(e),
        })

    return {
        "filename": name,
        "status": "scan_complete",
        "entities_found": result["hits"],
        "entity_types": result["entity_types"],
        "redacted_text": result["redacted_text"],
    }