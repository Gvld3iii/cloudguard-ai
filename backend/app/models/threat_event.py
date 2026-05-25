from pydantic import BaseModel
from typing import Optional

class ThreatEvent(BaseModel):
    event_type: str = 'unknown'
    source_ip: str = '0.0.0.0'
    actor: Optional[str] = None
    region: Optional[str] = None
    login_time: Optional[str] = None
    api_calls_last_minute: int = 0
    failed_logins: int = 0
    privileged_action: bool = False
