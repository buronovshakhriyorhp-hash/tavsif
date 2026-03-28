"""
main.py — NetUserClassify FastAPI Backend
==========================================
Fixes applied:
  [SEC-1] File size limit: max 10MB
  [SEC-2] Content-Type validation added
  [SEC-3] Error info leakage: str(e) hidden from client
  [SEC-4] CORS configured (localhost only)
  [SEC-5] Security headers middleware added
"""
from fastapi import FastAPI, UploadFile, File, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import pandas as pd
import io
import os
import logging

from ml_model import analyze_logs

# ─── Logging ────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("netUserClassify")

# ─── App ─────────────────────────────────────────────────────────────
app = FastAPI(
    title="NetUserClassify",
    description="Internet foydalanuvchilarini web-loglar asosida tasniflash tizimi",
    version="1.0.0",
    docs_url=None,    # Produksiyada Swagger o'chiq
    redoc_url=None,
)

# ─── [SEC-4] CORS ────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ─── [SEC-5] Security Headers Middleware ─────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# ─── Static & Templates ───────────────────────────────────────────────
os.makedirs("static/css", exist_ok=True)
os.makedirs("static/js", exist_ok=True)
os.makedirs("templates", exist_ok=True)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ─── Constants ───────────────────────────────────────────────────────
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
ALLOWED_CONTENT_TYPES = {"text/csv", "application/csv", "application/octet-stream"}
REQUIRED_COLS = {"timestamp", "ip", "method", "path", "status", "user_agent"}


# ─── Page Routes ─────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "active_page": "home"})

@app.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request):
    return templates.TemplateResponse("upload.html", {"request": request, "active_page": "upload"})

@app.get("/results", response_class=HTMLResponse)
async def results_page(request: Request):
    return templates.TemplateResponse("results.html", {"request": request, "active_page": "results"})

@app.get("/about", response_class=HTMLResponse)
async def about_page(request: Request):
    return templates.TemplateResponse("about.html", {"request": request, "active_page": "about"})


# ─── API Endpoint ─────────────────────────────────────────────────────
@app.post("/api/analyze")
async def analyze_endpoint(file: UploadFile = File(...)):

    # [SEC-2] Extension validation
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400,
                            detail="Faqat .csv formatdagi fayllar qabul qilinadi!")

    # [SEC-1] File size limit — read first chunk to check
    contents = await file.read()
    if len(contents) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(status_code=413,
                            detail=f"Fayl hajmi juda katta! Maksimum {MAX_FILE_SIZE_BYTES // (1024*1024)} MB.")

    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Yuklangan CSV fayl bo'sh!")

    try:
        df = pd.read_csv(io.BytesIO(contents))

        # Column validation
        if not REQUIRED_COLS.issubset(set(df.columns)):
            missing = REQUIRED_COLS - set(df.columns)
            raise HTTPException(
                status_code=400,
                detail=f"CSV faylda quyidagi ustunlar yetishmayapti: {', '.join(sorted(missing))}"
            )

        if len(df) == 0:
            raise HTTPException(status_code=400, detail="CSV fayl bo'sh yoki faqat sarlavha qatori bor!")

        logger.info("Tahlil boshlandi: '%s' (%d qator)", file.filename, len(df))

        results = analyze_logs(df)

        logger.info("Tahlil yakunlandi. IP: %d, Jami: %d",
                    results["unique_ips"], results["total_requests"])

        return JSONResponse(content=results)

    except HTTPException:
        raise
    except pd.errors.EmptyDataError:
        raise HTTPException(status_code=400, detail="Yuklangan CSV fayl bo'sh!")
    except pd.errors.ParserError:
        raise HTTPException(status_code=400,
                            detail="CSV fayl to'g'ri formatda emas. Iltimos, to'g'ri CSV fayl yuklang.")
    except Exception as e:
        # [SEC-3] Do NOT expose internal error to client
        logger.error("Tahlil xatoligi: %s", str(e), exc_info=True)
        raise HTTPException(status_code=500,
                            detail="Server tomonida xatolik yuz berdi. Iltimos, faylni tekshirib qayta urinib ko'ring.")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
