# Windows 에서 OpenSAST 실행하기 (WSL2 + Docker Desktop)

> OpenSAST 는 Windows 네이티브를 **공식 지원하지 않습니다**. 주요 분석 엔진
> (Semgrep/Opengrep)이 Windows 용 wheel 을 제공하지 않고, WeasyPrint 가
> GTK3 런타임을 요구하는 등 네이티브 설치가 복잡하기 때문입니다.
>
> 대신 **WSL2 + Docker Desktop** 조합을 사용하면 Linux 환경과 동일하게
> 전체 기능을 사용할 수 있습니다.

---

## 1. 사전 요구사항

| 항목 | 최소 버전 | 비고 |
|------|----------|------|
| Windows | 10 (2004+) 또는 11 | WSL2 지원 |
| CPU | x86_64 또는 ARM64 | 가상화(VT-x/AMD-V) 활성 |
| RAM | 16 GB 권장 | Ollama 로컬 LLM 사용 시 32 GB |
| 디스크 | 30 GB 여유 | 스캔 결과/이미지 저장 |
| 관리자 권한 | 필수 | WSL 설치 |

---

## 2. WSL2 설치

PowerShell 을 **관리자 권한** 으로 열고:

```powershell
wsl --install
```

완료 후 재부팅. 처음 실행 시 Ubuntu 22.04 가 기본 설치되며 리눅스 사용자
계정을 만들라고 묻습니다. 원하는 ID/비밀번호를 입력하세요.

설치 확인:

```powershell
wsl --status
wsl -l -v   # 배포판 목록 + 버전 표시 (VERSION=2 확인)
```

만약 `VERSION=1` 이면 WSL2 로 업그레이드:

```powershell
wsl --set-default-version 2
wsl --set-version Ubuntu-22.04 2
```

---

## 3. Docker Desktop 설치 + WSL2 통합

1. [Docker Desktop](https://www.docker.com/products/docker-desktop/) 설치
2. 설치 후 `Settings → Resources → WSL Integration` 열기
3. **Enable integration with my default WSL distro** 체크
4. 사용할 배포판(Ubuntu-22.04) 토글 ON
5. **Apply & Restart**

WSL 쉘(Ubuntu) 에서 확인:

```bash
docker version
docker compose version
```

두 명령이 모두 정상 출력되면 통합 완료.

---

## 4. 필수 도구 설치 (WSL Ubuntu 쉘)

```bash
sudo apt update
sudo apt install -y git curl build-essential
```

선택 — 호스트 네이티브에서 `pytest` 를 돌리고 싶다면 Python 과 WeasyPrint
시스템 의존성도 설치:

```bash
sudo apt install -y python3.12-venv python3-pip \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 shared-mime-info libffi-dev
```

---

## 5. OpenSAST 클론 + 실행

```bash
# 홈 디렉터리에 클론 (WSL 파일시스템을 사용하세요 — /mnt/c 는 매우 느림)
cd ~
git clone https://github.com/sungalex/OpenSAST.git
cd OpenSAST

# 환경변수 템플릿 복사
cp .env.example .env

# Docker Compose 로 전체 스택 기동
docker compose up -d --build
```

브라우저(Windows 호스트)에서 `http://localhost:8080` 접속 → 로그인:

- 이메일: `admin@opensast.local`
- 비밀번호: `opensast-admin`

---

## 6. 주의 사항

### 6.1 파일시스템 성능

**필수**: 프로젝트를 **WSL 파일시스템**(`~/OpenSAST`) 에 두세요. `/mnt/c/Users/...`
경로는 Windows 드라이브를 9P 프로토콜로 마운트한 것이라 파일 I/O 가
10~50배 느립니다.

### 6.2 포트 포워딩

Docker Desktop 이 WSL2 포트를 자동으로 Windows 호스트에 포워딩합니다.
`localhost:8080` 이 안 뜨면 PowerShell 에서:

```powershell
wsl --shutdown
```

실행 후 Docker Desktop 재시작.

### 6.3 메모리 사용 제어

WSL2 가 RAM 을 과도하게 점유하면 `%USERPROFILE%\.wslconfig` 파일 작성:

```ini
[wsl2]
memory=8GB
processors=4
swap=4GB
```

### 6.4 줄바꿈 (CRLF vs LF)

`git` 이 기본적으로 Windows 에서 CRLF 로 체크아웃합니다. WSL 에서 작업할
때는 LF 를 유지해야 하므로:

```bash
git config --global core.autocrlf input
```

또는 프로젝트 로컬:

```bash
cd ~/OpenSAST
git config core.autocrlf false
git add --renormalize .
```

`.gitattributes` 에 `* text=auto eol=lf` 를 추가하는 것도 방법입니다.

---

## 7. 개발 모드 (선택)

WSL 안에서 Python 가상환경을 만들고 직접 실행:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest -q   # 백엔드 테스트 136 건 전체 실행
```

VS Code 의 **WSL 확장**을 설치하면 Windows 쪽에서 편집하면서도 서버·터미널·
디버거가 WSL 안에서 구동되어 가장 매끄러운 개발 경험을 얻을 수 있습니다.

---

## 8. 트러블슈팅

| 증상 | 해결 |
|------|------|
| `docker compose up` 에서 권한 거부 | `sudo usermod -aG docker $USER` 후 WSL 재시작 |
| `localhost:8080` 무응답 | Docker Desktop Settings → Resources → WSL Integration 재확인, `wsl --shutdown` 후 Docker 재기동 |
| `pip install` 에서 SSL/네트워크 오류 | WSL 프록시 설정 필요: `~/.bashrc` 에 `export HTTPS_PROXY=...` |
| `apt update` 에서 hash mismatch | `sudo rm -rf /var/lib/apt/lists/* && sudo apt update` |
| 디스크 공간 부족 | Windows 의 WSL 가상 디스크 크기 자동 확장 — 대신 `docker system prune -af` 로 이미지 정리 |

---

## 9. 왜 Windows 네이티브를 지원하지 않는가?

| 의존성 | Windows 네이티브 상황 |
|--------|---------------------|
| **Semgrep/Opengrep** | 공식적으로 Windows 미지원. pip wheel 없음 |
| **WeasyPrint** | GTK3 런타임 수동 설치 필요, MSVC DLL 경로 이슈 |
| **Celery prefork** | Celery 4+ 에서 Windows 용 fork pool 미지원, `solo`/`threads` 만 가능 |
| **Spotbugs + JDK** | 설치는 되지만 경로 공백 이슈가 빈번 |
| **`uvloop`** | Windows 미지원 (자동으로 asyncio 기본 루프 사용) |

이 모든 이슈를 WSL2 가 한 번에 우회해주므로 공식 지원 경로로 선정했습니다.
