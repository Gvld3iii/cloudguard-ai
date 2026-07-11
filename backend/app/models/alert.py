from pydantic import BaseModel

class AlertDecision(BaseModel):
    action: str
    message: str
