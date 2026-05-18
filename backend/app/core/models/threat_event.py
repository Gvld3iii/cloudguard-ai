from typing import Optional

from pydantic import BaseModel, Field


class ThreatEvent(BaseModel):
    event_type: str = Field(..., description="Type of event being analyzed")
    source_ip: str = Field(..., description="Source IP address for the event")
    actor: Optional[str] = Field(default=None, description="User or service actor")
    region: Optional[str] = Field(default=None, description="Cloud region where the event originated")
    login_time: Optional[str] = Field(default=None, description="Timestamp of the login or activity")
    api_calls_last_minute: int = Field(
        default=0,
        ge=0,
        description="Number of API calls observed from the source in the last minute",
    )
    failed_logins: int = Field(
        default=0,
        ge=0,
        description="Number of failed login attempts associated with the event",
    )
    privileged_action: bool = Field(
        default=False,
        description="Whether the event involved a privileged or sensitive action",
    )