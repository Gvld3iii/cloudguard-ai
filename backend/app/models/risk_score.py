from pydantic import BaseModel

class RiskScore(BaseModel):
    score: float
    severity: str
    reasons: list = []
