"""행안부 구현단계 49개 보안약점 카탈로그.

본 모듈은 '소프트웨어 보안약점 진단가이드(KISA, 2021)' 구현단계 49개 항목을
Python 데이터 구조로 표현하며, 각 항목에 대응되는 CWE ID·분류·심각도·
진단 엔진 우선순위를 함께 담는다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """행안부 점검표 심각도 구분."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class MoisCategory(str, Enum):
    """구현단계 49개 항목의 7개 상위 분류."""

    INPUT_VALIDATION = "입력데이터 검증 및 표현"
    SECURITY_FEATURE = "보안기능"
    TIME_AND_STATE = "시간 및 상태"
    ERROR_HANDLING = "에러처리"
    CODE_ERROR = "코드오류"
    ENCAPSULATION = "캡슐화"
    API_MISUSE = "API 오용"


@dataclass(frozen=True)
class MoisItem:
    """행안부 점검표 단일 항목."""

    id: str
    name_kr: str
    name_en: str
    category: MoisCategory
    cwe_ids: tuple[str, ...]
    severity: Severity
    primary_engines: tuple[str, ...] = field(default_factory=tuple)
    secondary_engines: tuple[str, ...] = field(default_factory=tuple)
    description: str = ""

    @property
    def primary_cwe(self) -> str:
        return self.cwe_ids[0] if self.cwe_ids else ""


MOIS_ITEMS: tuple[MoisItem, ...] = (
    # 입력데이터 검증 및 표현 (18개)
    MoisItem(
        id="SR1-1",
        name_kr="SQL 삽입",
        name_en="SQL Injection",
        category=MoisCategory.INPUT_VALIDATION,
        cwe_ids=("CWE-89",),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
        secondary_engines=("codeql", "spotbugs"),
        description=(
            "데이터베이스와 연동된 웹 애플리케이션에서 입력된 데이터에 대한 유효성 "
            "검증을 하지 않을 경우 공격자가 입력 폼 및 URL 파라미터를 통해 SQL 문을 "
            "삽입하여 데이터베이스를 조작할 수 있는 보안약점"
        ),
    ),
    MoisItem(
        id="SR1-2",
        name_kr="경로 조작 및 자원 삽입",
        name_en="Path Traversal and Resource Injection",
        category=MoisCategory.INPUT_VALIDATION,
        cwe_ids=("CWE-22", "CWE-73"),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
        secondary_engines=("codeql", "spotbugs"),
        description="외부 입력을 통해 파일 또는 자원의 이름/경로를 조작하여 "
        "허가되지 않은 자원에 접근할 수 있는 보안약점",
    ),
    MoisItem(
        id="SR1-3",
        name_kr="크로스사이트 스크립트",
        name_en="Cross-Site Scripting (XSS)",
        category=MoisCategory.INPUT_VALIDATION,
        cwe_ids=("CWE-79",),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
        secondary_engines=("codeql",),
        description="검증되지 않은 외부 입력을 동적 웹 페이지 생성에 사용할 경우 "
        "공격자가 스크립트를 삽입해 사용자 브라우저에서 실행할 수 있는 보안약점",
    ),
    MoisItem(
        id="SR1-4",
        name_kr="운영체제 명령어 삽입",
        name_en="OS Command Injection",
        category=MoisCategory.INPUT_VALIDATION,
        cwe_ids=("CWE-78",),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
        secondary_engines=("codeql",),
        description="외부 입력이 OS 명령어 실행에 직접 사용되어 의도하지 않은 "
        "명령어가 수행될 수 있는 보안약점",
    ),
    MoisItem(
        id="SR1-5",
        name_kr="위험한 형식 파일 업로드",
        name_en="Unrestricted File Upload",
        category=MoisCategory.INPUT_VALIDATION,
        cwe_ids=("CWE-434",),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
        description="실행 가능한 파일 형식의 업로드를 허용하여 원격 코드 실행이 "
        "가능한 보안약점",
    ),
    MoisItem(
        id="SR1-6",
        name_kr="신뢰되지 않는 URL 주소로 자동접속 연결",
        name_en="Open Redirect",
        category=MoisCategory.INPUT_VALIDATION,
        cwe_ids=("CWE-601",),
        severity=Severity.MEDIUM,
        primary_engines=("opengrep",),
        secondary_engines=("codeql",),
    ),
    MoisItem(
        id="SR1-7",
        name_kr="부적절한 XML 외부개체 참조(XXE)",
        name_en="XML External Entity (XXE)",
        category=MoisCategory.INPUT_VALIDATION,
        cwe_ids=("CWE-611",),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
        secondary_engines=("codeql", "spotbugs"),
    ),
    MoisItem(
        id="SR1-8",
        name_kr="XML 삽입",
        name_en="XML Injection",
        category=MoisCategory.INPUT_VALIDATION,
        cwe_ids=("CWE-91",),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
    ),
    MoisItem(
        id="SR1-9",
        name_kr="LDAP 삽입",
        name_en="LDAP Injection",
        category=MoisCategory.INPUT_VALIDATION,
        cwe_ids=("CWE-90",),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
    ),
    MoisItem(
        id="SR1-10",
        name_kr="크로스사이트 요청 위조(CSRF)",
        name_en="Cross-Site Request Forgery",
        category=MoisCategory.INPUT_VALIDATION,
        cwe_ids=("CWE-352",),
        severity=Severity.MEDIUM,
        primary_engines=("opengrep",),
    ),
    MoisItem(
        id="SR1-11",
        name_kr="서버사이드 요청 위조(SSRF)",
        name_en="Server-Side Request Forgery",
        category=MoisCategory.INPUT_VALIDATION,
        cwe_ids=("CWE-918",),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
        secondary_engines=("codeql",),
    ),
    MoisItem(
        id="SR1-12",
        name_kr="HTTP 응답분할",
        name_en="HTTP Response Splitting",
        category=MoisCategory.INPUT_VALIDATION,
        cwe_ids=("CWE-113",),
        severity=Severity.MEDIUM,
        primary_engines=("opengrep",),
    ),
    MoisItem(
        id="SR1-13",
        name_kr="정수형 오버플로우",
        name_en="Integer Overflow",
        category=MoisCategory.INPUT_VALIDATION,
        cwe_ids=("CWE-190",),
        severity=Severity.MEDIUM,
        primary_engines=("codeql",),
        secondary_engines=("opengrep",),
    ),
    MoisItem(
        id="SR1-14",
        name_kr="보안기능 결정에 사용되는 부적절한 입력값",
        name_en="Improper Input Validation for Security Decisions",
        category=MoisCategory.INPUT_VALIDATION,
        cwe_ids=("CWE-807",),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
    ),
    MoisItem(
        id="SR1-15",
        name_kr="메모리 버퍼 오버플로우",
        name_en="Buffer Overflow",
        category=MoisCategory.INPUT_VALIDATION,
        cwe_ids=("CWE-119", "CWE-120"),
        severity=Severity.HIGH,
        primary_engines=("codeql",),
    ),
    MoisItem(
        id="SR1-16",
        name_kr="포맷 스트링 삽입",
        name_en="Format String Injection",
        category=MoisCategory.INPUT_VALIDATION,
        cwe_ids=("CWE-134",),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
        secondary_engines=("codeql",),
    ),
    MoisItem(
        id="SR1-17",
        name_kr="코드 삽입",
        name_en="Code Injection",
        category=MoisCategory.INPUT_VALIDATION,
        cwe_ids=("CWE-94",),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
        secondary_engines=("codeql",),
    ),
    MoisItem(
        id="SR1-18",
        name_kr="신뢰할 수 없는 데이터의 역직렬화",
        name_en="Deserialization of Untrusted Data",
        category=MoisCategory.INPUT_VALIDATION,
        cwe_ids=("CWE-502",),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
        secondary_engines=("spotbugs",),
    ),
    # 보안기능 (12개)
    MoisItem(
        id="SR2-1",
        name_kr="적절한 인증 없는 중요기능 허용",
        name_en="Missing Authentication for Critical Function",
        category=MoisCategory.SECURITY_FEATURE,
        cwe_ids=("CWE-306",),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
    ),
    MoisItem(
        id="SR2-2",
        name_kr="부적절한 인가",
        name_en="Improper Authorization",
        category=MoisCategory.SECURITY_FEATURE,
        cwe_ids=("CWE-285",),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
    ),
    MoisItem(
        id="SR2-3",
        name_kr="중요한 자원에 대한 잘못된 권한 설정",
        name_en="Incorrect Permission Assignment for Critical Resource",
        category=MoisCategory.SECURITY_FEATURE,
        cwe_ids=("CWE-732",),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
    ),
    MoisItem(
        id="SR2-4",
        name_kr="취약한 암호화 알고리즘 사용",
        name_en="Use of Broken or Risky Cryptographic Algorithm",
        category=MoisCategory.SECURITY_FEATURE,
        cwe_ids=("CWE-327",),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
        secondary_engines=("spotbugs",),
    ),
    MoisItem(
        id="SR2-5",
        name_kr="암호화되지 않은 중요정보",
        name_en="Cleartext Storage of Sensitive Information",
        category=MoisCategory.SECURITY_FEATURE,
        cwe_ids=("CWE-311", "CWE-312"),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
    ),
    MoisItem(
        id="SR2-6",
        name_kr="하드코드된 중요정보",
        name_en="Hard-coded Credentials",
        category=MoisCategory.SECURITY_FEATURE,
        cwe_ids=("CWE-798", "CWE-259"),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
        secondary_engines=("spotbugs",),
    ),
    MoisItem(
        id="SR2-7",
        name_kr="충분하지 않은 키 길이 사용",
        name_en="Inadequate Encryption Strength",
        category=MoisCategory.SECURITY_FEATURE,
        cwe_ids=("CWE-326",),
        severity=Severity.MEDIUM,
        primary_engines=("opengrep",),
        secondary_engines=("spotbugs",),
    ),
    MoisItem(
        id="SR2-8",
        name_kr="적절하지 않은 난수값 사용",
        name_en="Use of Insufficiently Random Values",
        category=MoisCategory.SECURITY_FEATURE,
        cwe_ids=("CWE-330", "CWE-338"),
        severity=Severity.MEDIUM,
        primary_engines=("opengrep",),
        secondary_engines=("spotbugs",),
    ),
    MoisItem(
        id="SR2-9",
        name_kr="취약한 비밀번호 허용",
        name_en="Weak Password Requirements",
        category=MoisCategory.SECURITY_FEATURE,
        cwe_ids=("CWE-521",),
        severity=Severity.MEDIUM,
        primary_engines=("opengrep",),
    ),
    MoisItem(
        id="SR2-10",
        name_kr="부적절한 전자서명 확인",
        name_en="Improper Verification of Cryptographic Signature",
        category=MoisCategory.SECURITY_FEATURE,
        cwe_ids=("CWE-347",),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
    ),
    MoisItem(
        id="SR2-11",
        name_kr="부적절한 인증서 유효성 검증",
        name_en="Improper Certificate Validation",
        category=MoisCategory.SECURITY_FEATURE,
        cwe_ids=("CWE-295",),
        severity=Severity.HIGH,
        primary_engines=("opengrep",),
    ),
    MoisItem(
        id="SR2-12",
        name_kr="사용자 하드디스크에 저장되는 쿠키를 통한 정보노출",
        name_en="Sensitive Cookie without Secure Attribute",
        category=MoisCategory.SECURITY_FEATURE,
        cwe_ids=("CWE-614",),
        severity=Severity.MEDIUM,
        primary_engines=("opengrep",),
    ),
    # 시간 및 상태 (2개)
    MoisItem(
        id="SR3-1",
        name_kr="검사시점과 사용시점(TOCTOU)",
        name_en="Time-of-check to Time-of-use",
        category=MoisCategory.TIME_AND_STATE,
        cwe_ids=("CWE-367",),
        severity=Severity.MEDIUM,
        primary_engines=("codeql",),
    ),
    MoisItem(
        id="SR3-2",
        name_kr="종료되지 않는 반복문 또는 재귀함수",
        name_en="Unbounded Loop or Recursion",
        category=MoisCategory.TIME_AND_STATE,
        cwe_ids=("CWE-835", "CWE-674"),
        severity=Severity.MEDIUM,
        primary_engines=("codeql",),
    ),
    # 에러처리 (3개)
    MoisItem(
        id="SR4-1",
        name_kr="오류 메시지를 통한 정보노출",
        name_en="Information Exposure Through Error Message",
        category=MoisCategory.ERROR_HANDLING,
        cwe_ids=("CWE-209",),
        severity=Severity.MEDIUM,
        primary_engines=("opengrep",),
        secondary_engines=("spotbugs",),
    ),
    MoisItem(
        id="SR4-2",
        name_kr="오류 상황 대응 부재",
        name_en="Missing Error Handling",
        category=MoisCategory.ERROR_HANDLING,
        cwe_ids=("CWE-391", "CWE-703"),
        severity=Severity.MEDIUM,
        primary_engines=("opengrep",),
        secondary_engines=("spotbugs",),
    ),
    MoisItem(
        id="SR4-3",
        name_kr="부적절한 예외처리",
        name_en="Improper Exception Handling",
        category=MoisCategory.ERROR_HANDLING,
        cwe_ids=("CWE-396", "CWE-397"),
        severity=Severity.MEDIUM,
        primary_engines=("opengrep",),
        secondary_engines=("spotbugs",),
    ),
    # 코드오류 (7개)
    MoisItem(
        id="SR5-1",
        name_kr="Null Pointer 역참조",
        name_en="Null Pointer Dereference",
        category=MoisCategory.CODE_ERROR,
        cwe_ids=("CWE-476",),
        severity=Severity.MEDIUM,
        primary_engines=("spotbugs",),
        secondary_engines=("codeql",),
    ),
    MoisItem(
        id="SR5-2",
        name_kr="부적절한 자원 해제",
        name_en="Improper Resource Shutdown or Release",
        category=MoisCategory.CODE_ERROR,
        cwe_ids=("CWE-404", "CWE-772"),
        severity=Severity.MEDIUM,
        primary_engines=("spotbugs",),
        secondary_engines=("codeql",),
    ),
    MoisItem(
        id="SR5-3",
        name_kr="해제된 자원 사용",
        name_en="Use After Free",
        category=MoisCategory.CODE_ERROR,
        cwe_ids=("CWE-416",),
        severity=Severity.HIGH,
        primary_engines=("codeql",),
    ),
    MoisItem(
        id="SR5-4",
        name_kr="초기화되지 않은 변수 사용",
        name_en="Use of Uninitialized Variable",
        category=MoisCategory.CODE_ERROR,
        cwe_ids=("CWE-457",),
        severity=Severity.MEDIUM,
        primary_engines=("codeql",),
        secondary_engines=("spotbugs",),
    ),
    MoisItem(
        id="SR5-5",
        name_kr="경쟁조건 (Race Condition)",
        name_en="Race Condition",
        category=MoisCategory.CODE_ERROR,
        cwe_ids=("CWE-362",),
        severity=Severity.MEDIUM,
        primary_engines=("codeql",),
    ),
    MoisItem(
        id="SR5-6",
        name_kr="제대로 된 배열/포인터 사용 미흡",
        name_en="Incorrect Pointer/Array Usage",
        category=MoisCategory.CODE_ERROR,
        cwe_ids=("CWE-125", "CWE-787"),
        severity=Severity.HIGH,
        primary_engines=("codeql",),
    ),
    MoisItem(
        id="SR5-7",
        name_kr="반환값 검증 누락",
        name_en="Unchecked Return Value",
        category=MoisCategory.CODE_ERROR,
        cwe_ids=("CWE-252",),
        severity=Severity.LOW,
        primary_engines=("spotbugs",),
        secondary_engines=("codeql",),
    ),
    # 캡슐화 (5개)
    MoisItem(
        id="SR6-1",
        name_kr="잘못된 세션에 의한 데이터 정보노출",
        name_en="Data Leak Through Incorrect Session",
        category=MoisCategory.ENCAPSULATION,
        cwe_ids=("CWE-488",),
        severity=Severity.MEDIUM,
        primary_engines=("opengrep",),
    ),
    MoisItem(
        id="SR6-2",
        name_kr="제거되지 않고 남은 디버그 코드",
        name_en="Leftover Debug Code",
        category=MoisCategory.ENCAPSULATION,
        cwe_ids=("CWE-489",),
        severity=Severity.LOW,
        primary_engines=("opengrep",),
    ),
    MoisItem(
        id="SR6-3",
        name_kr="시스템 데이터 정보노출",
        name_en="System Information Leak",
        category=MoisCategory.ENCAPSULATION,
        cwe_ids=("CWE-497",),
        severity=Severity.LOW,
        primary_engines=("opengrep",),
    ),
    MoisItem(
        id="SR6-4",
        name_kr="Public 메소드로부터 반환된 Private 배열",
        name_en="Private Array Returned From Public Method",
        category=MoisCategory.ENCAPSULATION,
        cwe_ids=("CWE-495",),
        severity=Severity.LOW,
        primary_engines=("spotbugs",),
    ),
    MoisItem(
        id="SR6-5",
        name_kr="Private 배열에 Public 데이터 할당",
        name_en="Public Data Assigned to Private Array",
        category=MoisCategory.ENCAPSULATION,
        cwe_ids=("CWE-496",),
        severity=Severity.LOW,
        primary_engines=("spotbugs",),
    ),
    # API 오용 (2개)
    MoisItem(
        id="SR7-1",
        name_kr="DNS Lookup에 의존한 보안결정",
        name_en="Reliance on DNS Lookups",
        category=MoisCategory.API_MISUSE,
        cwe_ids=("CWE-350", "CWE-247"),
        severity=Severity.MEDIUM,
        primary_engines=("opengrep",),
    ),
    MoisItem(
        id="SR7-2",
        name_kr="취약한 API 사용",
        name_en="Use of Vulnerable API",
        category=MoisCategory.API_MISUSE,
        cwe_ids=("CWE-676", "CWE-242"),
        severity=Severity.MEDIUM,
        primary_engines=("opengrep",),
        secondary_engines=("spotbugs",),
    ),
)


MOIS_ITEMS_BY_ID: dict[str, MoisItem] = {item.id: item for item in MOIS_ITEMS}


def get_item(mois_id: str) -> MoisItem | None:
    """MOIS ID로 단일 항목 조회."""

    return MOIS_ITEMS_BY_ID.get(mois_id)


def items_for_cwe(cwe_id: str) -> list[MoisItem]:
    """CWE ID에 매핑되는 모든 MOIS 항목 반환."""

    normalized = _normalize_cwe(cwe_id)
    return [
        item
        for item in MOIS_ITEMS
        if any(_normalize_cwe(cwe) == normalized for cwe in item.cwe_ids)
    ]


def _normalize_cwe(cwe: str) -> str:
    cwe = cwe.strip().upper()
    if not cwe:
        return ""
    if cwe.isdigit():
        return f"CWE-{int(cwe)}"
    if not cwe.startswith("CWE-"):
        return cwe
    return f"CWE-{int(cwe[4:])}"


def ensure_49_items() -> None:
    """행안부 49개 항목 수 검증을 위한 헬퍼 (테스트·자가진단용)."""

    if len(MOIS_ITEMS) != 49:
        raise AssertionError(
            f"MOIS catalog must contain exactly 49 items, found {len(MOIS_ITEMS)}"
        )
