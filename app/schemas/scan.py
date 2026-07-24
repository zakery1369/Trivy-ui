from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    image: str = Field(..., min_length=1)
    pull_if_missing: bool = True


class AIRecommendRequest(BaseModel):
    scan_id: str = Field(..., min_length=1)
    provider: str = Field(..., min_length=1)
    base_url: str = Field(..., min_length=1)
    model: str = Field(..., min_length=1)
    api_key: str = ""
    language: str = "fa"

