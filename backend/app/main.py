import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.db.database import init_db
from app.routes.analyze import router as analyze_router
from app.services.ml_model import load_model

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("phishaegis")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    logger.info("=" * 60)
    logger.info("PhishAegis — Starting up")
    logger.info("=" * 60)

    logger.info("Initializing database...")
    init_db()

    logger.info("Loading ML model...")
    model_loaded = load_model()
    if model_loaded:
        logger.info("ML model loaded successfully")
    else:
        logger.warning("ML model not available — rule-based detection only")

    logger.info("PhishAegis is ready")
    logger.info("=" * 60)

    yield

    logger.info("PhishAegis — Shutting down")


app = FastAPI(
    title="PhishAegis",
    description="Real-Time Phishing Detection & Forensic Email Analysis System",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze_router)


@app.get("/")
async def root():
    """Health check endpoint."""
    return {
        "name": "PhishAegis",
        "version": "1.0.0",
        "status": "operational",
        "description": "Real-Time Phishing Detection & Forensic Email Analysis System",
    }


@app.get("/health")
async def health_check():
    """Detailed health check."""
    from app.services.ml_model import is_model_loaded

    return {
        "status": "healthy",
        "ml_model_loaded": is_model_loaded(),
        "database": "connected",
    }
