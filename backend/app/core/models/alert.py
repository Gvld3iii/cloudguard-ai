from pydantic import BaseModel, Field


class AlertDecision(BaseModel):
    action: str = Field(
        ...,
        description="Recommended action based on the evaluated risk",
    )
    message: str = Field(
        ...,
        description="Explanation of why this action was chosen",
    )