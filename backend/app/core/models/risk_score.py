from pydantic import BaseModel, Field


class RiskScore(BaseModel):
    score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Calculated risk score from 0 to 100",
    )
    severity: str = Field(
        ...,
        description="Severity classification for the calculated risk",
    )
    reasons: list[str] = Field(
        default_factory=list,
        description="List of reasons that contributed to the risk score",
    )