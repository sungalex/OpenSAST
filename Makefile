# OpenSAST 개발 워크플로 도우미.
# Docker compose 주변의 반복 명령을 짧은 타겟으로 노출한다.

.PHONY: help up down restart rebuild logs ps clean

help:
	@echo "OpenSAST — docker compose 도우미"
	@echo ""
	@echo "사용법: make <target>"
	@echo ""
	@echo "  up       전체 스택 기동 (detached)"
	@echo "  down     전체 스택 중지 · 컨테이너·네트워크 제거"
	@echo "  restart  전체 스택 재시작 (이미지 재빌드 없음)"
	@echo "  rebuild  이미지 재빌드 + 기동 + 고아 <none> 이미지 정리"
	@echo "  logs     api · worker · frontend 로그 팔로우"
	@echo "  ps       현재 컨테이너 상태"
	@echo "  clean    down + 고아 이미지·빌드 캐시 정리 (볼륨 보존)"

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart

# docker compose build 는 이전 빌드의 이미지를 `<none>` 으로 남기므로
# 재빌드 후 dangling 이미지를 즉시 정리한다.
rebuild:
	docker compose build
	docker compose up -d
	docker image prune -f

logs:
	docker compose logs -f api worker frontend

ps:
	docker compose ps

clean:
	docker compose down
	docker image prune -f
	docker builder prune -f
