"""API 요청·응답 Pydantic 스키마."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

# 내부망 도메인(.local, .internal 등)도 허용하기 위해 Pydantic EmailStr 대신 느슨한
# 자체 검증을 사용한다. email-validator 는 IANA special-use 도메인을 거부하여
# admin@aisast.local 같은 기본 부트스트랩 계정을 사용할 수 없게 만든다.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _validate_email(v: str) -> str:
    v = v.strip()
    if not _EMAIL_RE.match(v):
        raise ValueError("invalid email format")
    return v.lower()


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        return _validate_email(v)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class UserCreate(BaseModel):
    email: str
    password: str = Field(min_length=8)
    display_name: str = ""
    role: str = "analyst"

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        return _validate_email(v)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    display_name: str
    role: str
    is_active: bool


class ProjectCreate(BaseModel):
    name: str
    description: str = ""
    repo_url: str = ""
    default_language: str | None = None


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    repo_url: str
    default_language: str | None
    created_at: datetime


class ScanCreate(BaseModel):
    project_id: int
    source_path: str
    language_hint: str | None = None
    enable_second_pass: bool = True
    enable_triage: bool = True


class GitScanCreate(BaseModel):
    project_id: int
    git_url: str
    branch: str | None = None
    language_hint: str | None = None
    enable_second_pass: bool = True
    enable_triage: bool = True

    @field_validator("git_url")
    @classmethod
    def _check_git_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("git_url is required")
        lowered = v.lower()
        if not (
            lowered.startswith("http://")
            or lowered.startswith("https://")
            or lowered.startswith("git@")
            or lowered.startswith("ssh://")
        ):
            raise ValueError(
                "git_url must start with http(s)://, ssh://, or git@"
            )
        return v


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: int
    status: str
    source_path: str
    started_at: datetime | None
    finished_at: datetime | None
    engine_stats: dict[str, Any] = {}
    mois_coverage: dict[str, Any] = {}
    error: str | None = None


class TriageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    verdict: str
    fp_probability: int
    rationale: str
    recommended_fix: str | None
    patched_code: str | None
    model: str


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: str
    engine: str
    severity: str
    message: str
    file_path: str
    start_line: int
    end_line: int | None
    cwe_ids: list[str]
    mois_id: str | None
    category: str | None
    language: str | None
    snippet: str | None
    triage: TriageOut | None = None


class MoisItemOut(BaseModel):
    id: str
    name_kr: str
    name_en: str
    category: str
    cwe_ids: list[str]
    severity: str
    primary_engines: list[str]
    secondary_engines: list[str]
    description: str
