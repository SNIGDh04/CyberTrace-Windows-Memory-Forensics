from pydantic import BaseModel, Field

from backend.config import SUPPORTED_PLUGINS


class CaseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class AnalyzeRequest(BaseModel):
    case_id: str = Field(min_length=1, max_length=64)
    plugins: list[str] = Field(
        default_factory=lambda: list(SUPPORTED_PLUGINS), min_length=1, max_length=7
    )