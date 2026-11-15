# Протокол доступных проверок, 2026-11-13

Успешно: Rust debug build всего workspace, fmt check, Clippy -D warnings;
Python unittest 9/9; shell syntax; Compose configuration rendering (base и временный generated S3 IPv6 override);
Babel syntax parse 13 TypeScript/TSX файлов.

Полный cargo test: 19 passed, 8 failed, 2 ignored. Восемь ошибок начинаются в
wiremock MockServer::start(): OS error 1, Operation not permitted при bind.
Ignored: queue_and_dedup и cookie_csrf_rbac_logout_workflow (требуют отдельной БД).
Запуск без network mock tests дал 19 passed; это не полный успешный cargo test.

Frontend npm ci: EUSAGE, отсутствует package-lock.json.
Попытка offline npm resolution после чтения локального cache: ENOTCACHED для
@tanstack/react-query. Проверка registry: EAI_AGAIN registry.npmjs.org.
Build: tsc not found. Test: vitest not found. Настоящий frontend build не получен.

Compose config с RIZENVULN_ENV_FILE=.env.example и --env-file .env.example прошёл.
Compose build/up/ps: permission denied при подключении к /var/run/docker.sock.
Также Compose сообщил, что buildx не установлен. Контейнеры не создавались.

Внешние сервисы, runtime Trivy, миграции и реальный браузер не проверены.
Полное описание состояния и дальнейшие команды: implementation-status.md и README.
