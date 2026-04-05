from fastapi import APIRouter
from backend.app.config import settings
from backend.app.logger import get_logger

router = APIRouter()
logger = get_logger("routes_health")


@router.get("/health")
def health_check():
    logger.info("Health check endpoint hit")

    return {
        "status": "ok",
        "service": settings.APP_NAME,
        "environment": settings.APP_ENV,
    }