# 트러블슈팅

> 이 문서는 `docs/USER_GUIDE.md`(1,926줄 단일 파일)를 독자별로 분할한 것이다
> ([ADR-0007](../adr/0007-documentation-architecture.md)).

---

## 트러블슈팅

### SpotBugs가 결과를 내지 않는다
`.class` 디렉터리가 없으면 스킵된다. Gradle/Maven 빌드를 먼저 실행해
`build/classes` 또는 `target/classes` 를 생성하세요.

### CodeQL 쿼리팩 다운로드 실패
`codeql database analyze` 에 `--download` 플래그가 기본으로 포함돼 있다. 오프라인
환경에서는 `codeql pack download codeql/java-queries` 로 사전 캐시하세요.

### WeasyPrint ImportError
pango/cairo 시스템 라이브러리가 필요하다. Docker 이미지에는 포함돼 있으나,
로컬 macOS에서는 `brew install pango cairo` 를 수행하고 venv 재생성이 필요할 수 있다. 실패 시 `reports/pdf.py` 가 HTML 바이트를 폴백으로 반환한다.

### bcrypt / passlib 오류
openSAST는 **bcrypt 를 직접 사용**하므로 passlib 가 설치되어 있어도 영향이 없다.
구버전에서 업그레이드했다면 `pip uninstall passlib` 후 `pip install -e '.[dev]'`
재실행을 권장한다.

### Docker 빌드에서 `openjdk-17-jre-headless` 실패
Debian trixie 이미지는 JDK 17을 제공하지 않는다. Dockerfile은 `openjdk-21-jre-headless` 를 사용한다. 수정한 경우 `docker compose build --no-cache api`.

### 로그인 422 Unprocessable Entity / "이메일 또는 비밀번호를 확인하세요"
증상: 프론트엔드에서 올바른 계정으로 로그인해도 실패. API 로그에
`POST /api/auth/login HTTP/1.1 422 Unprocessable Entity` 가 찍힘.

원인: Pydantic `EmailStr` 이 내부적으로 `email-validator` 라이브러리를 호출하는데,
이 라이브러리는 IANA special-use TLD 인 `.local` 을 "special-use or reserved
name" 으로 거부한다. `admin@opensast.local` 같은 기본 부트스트랩 계정 이메일이
422 로 차단되는 이유다.

해결: `opensast/api/schemas.py` 는 `EmailStr` 대신 느슨한 정규식 검증
(`^[^@\s]+@[^@\s]+\.[^@\s]+$`) 을 사용한다. `LoginRequest`·`UserCreate`·`UserOut`
가 모두 일반 `str` 타입 + `field_validator` 조합으로 정의돼 있으며, 입력값은
소문자로 정규화된다. `.local`·`.internal`·사내 도메인 모두 허용된다.

직접 검증:

```bash
curl -sS -X POST http://127.0.0.1:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@opensast.local","password":"opensast-admin"}'
# → {"access_token":"eyJ...","token_type":"bearer","role":"admin"}
```

### Vite 가 "ready" 로그까지 찍고도 브라우저 응답이 없음 (D-state hang)
증상: `docker compose logs frontend` 에 `VITE v5.x ready in Xms` 가 뜨는데
`curl http://127.0.0.1:8080/` 은 타임아웃, 컨테이너 내부에서 `wget` 도 타임아웃.
`docker compose exec frontend top` 으로 보면 node 프로세스가 **`D` 상태**에
수 GB VSZ 를 차지하고 있다. `netstat -ltn` 의 8080 라인에서 `Recv-Q` 가 0 이
아닌 값(예: 46)이면 확정.

원인: 호스트 `./frontend` 바인드 마운트 + chokidar 폴링 + macOS osxfs 가 파일
스캔으로 I/O 를 포화시켜 Vite 이벤트 루프가 디스크 대기 상태에 묶인다.

해결: 현재 `docker-compose.yml` 에는 바인드 마운트와 `CHOKIDAR_USEPOLLING` 이
모두 제거되어 있고, `vite.config.ts` 에서 `watch.usePolling=false` + node_modules/
dist/.vite 를 워치 대상에서 빼도록 설정되어 있다. 만약 구 설정이 잔존한다면:

```bash
docker compose kill frontend
docker compose rm -f frontend
docker volume rm aisast_opensast-node-modules 2>/dev/null
docker compose up -d --build --force-recreate --no-deps frontend
curl -sS http://127.0.0.1:8080/ -o /dev/null -w "HTTP %{http_code}\n"
```

결과가 `HTTP 200` 이면 정상. 이 모드에서는 HMR 이 없으므로 소스 수정 후에는
반드시 `docker compose build frontend && docker compose up -d frontend` 로
이미지를 리빌드해야 한다.

### `http://localhost:8080` 가 컨테이너에선 떠 있는데 브라우저에서만 안 열림
Vite 로그에 `VITE v5.x ready … Local: http://localhost:8080/` 까지 떴는데도
호스트 브라우저에서 접속이 안 된다면 원인은 대개 둘 중 하나다.

1. **macOS `localhost` IPv6 vs IPv4**: macOS에서는 `localhost` 가 먼저 `::1` 로
   해석되는데 Docker Desktop의 포트 퍼블리시는 IPv4(`0.0.0.0`)에만 적용된다.
   브라우저 주소창에 `http://127.0.0.1:8080/` 를 넣으면 바로 뜬다.
   Compose에는 `ports: "0.0.0.0:8080:8080"` 로 IPv4 바인딩을 명시해 두었다.
2. **API 프록시 타겟**: Vite의 `/api` 프록시는 *Vite 프로세스*가 호출하므로
   컨테이너 내부에서는 `http://localhost:8000` 이 아니라 `http://api:8000` 으로
   가야 한다. `VITE_API_TARGET` 환경변수로 주입되며, `vite.config.ts` 는
   해당 값이 없으면 로컬 `http://localhost:8000` 을 사용한다.

점검 명령:

```bash
# 호스트에서 IPv4로 직접
curl -v http://127.0.0.1:8080/

# 컨테이너 내부에서 자기 자신
docker compose exec frontend wget -qO- http://127.0.0.1:8080 | head

# 포트 퍼블리시 확인 — "0.0.0.0:8080->8080/tcp" 가 보여야 함
docker compose ps frontend
```

### 프론트엔드(http://localhost:8080)가 응답하지 않음
이전 버전 Compose는 `node:20-alpine` 이미지를 그대로 띄우고 바인드 마운트된
호스트 `frontend/` 안에서 `npm install` 을 매 기동 시 실행했다. macOS Docker
Desktop의 osxfs 바인드 마운트가 느려 `npm install` 이 수 분 간 멈춘 것처럼
보이고 로그도 버퍼링되어 출력되지 않는 문제가 있었다.

현재는 **전용 `frontend/Dockerfile`** 이 `node_modules` 를 빌드 타임에 설치하고,
Compose는 `node_modules` 를 named volume(`opensast-node-modules`)으로 올려
호스트 바인드와 충돌을 차단한다. Vite dev 서버는
`--host 0.0.0.0 --port 8080 --strictPort` 로 기동되고 `CHOKIDAR_USEPOLLING=true`
환경변수로 macOS 파일 변경 감지를 안정화한다.

디버깅 절차:

```bash
# 1) 컨테이너 상태
docker compose ps frontend

# 2) 실시간 로그 — "VITE v5.x  ready in Xms" 메시지가 보여야 정상
docker compose logs -f frontend

# 3) 내부에서 Vite 응답 확인
docker compose exec frontend wget -qO- http://127.0.0.1:8080 | head

# 4) node_modules 볼륨이 오염됐을 때 깨끗이 재생성
docker compose down
docker volume rm aisast_opensast-node-modules
docker compose up --build frontend

# 5) 8080 포트가 다른 프로세스에 점유된 경우(strictPort 로 즉시 실패)
lsof -i :8080
```

`package.json` 에 새 의존성을 추가했다면 **반드시** 이미지를 리빌드하세요:

```bash
docker compose build frontend
docker compose up -d frontend
```

### 로그인 403 / 401
부트스트랩 관리자가 생성되었는지 확인: API 로그에 `bootstrap admin created: …`
경고 메시지가 있어야 한다. 존재하지 않으면 `opensast init-db` 를 실행하거나
`docker compose exec api opensast init-db` 를 사용.

---
