import os


class Settings:
    APP_NAME = os.getenv("APP_NAME", "CloudGuard AI")
    APP_ENV = os.getenv("APP_ENV", "dev")
    APP_HOST = os.getenv("APP_HOST", "127.0.0.1")
    APP_PORT = int(os.getenv("APP_PORT", "8000"))
    RISK_BLOCK_THRESHOLD = int(os.getenv("RISK_BLOCK_THRESHOLD", "80"))
    RISK_ALERT_THRESHOLD = int(os.getenv("RISK_ALERT_THRESHOLD", "60"))


settings = Settings()