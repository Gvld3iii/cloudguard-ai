from fastapi import FastAPI
from backend.app.api.routes_health import router as health_router
from backend.app.api.routes_simulate import router as simulate_router
from backend.app.api.routes_threats import router as threats_router
from backend.app.config import settings
from backend.app.logger import get_logger

logger = get_logger("main")

app = FastAPI(
    title=settings.APP_NAME,
    description="CloudGuard AI backend for threat simulation, risk scoring, and response decisions.",
    version="0.1.0",
)

app.include_router(health_router)
app.include_router(threats_router)
app.include_router(simulate_router)


@app.get("/")
def root():
    logger.info("Root endpoint hit")

    return {
        "message": f"{settings.APP_NAME} backend is running",
        "environment": settings.APP_ENV,
        "docs_url": "/docs",
    }