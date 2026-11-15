# Развёртывание

Начните с README. Compose создаёт только собственный project `rizenvuln`.
Контейнеры: rizenvuln-api, rizenvuln-worker, rizenvuln-postgres (имена Docker
дополнены Compose project/index). Named volumes: postgres-data и trivy-cache.
PostgreSQL не публикует порт, находится в internal network database.
API/Worker также подключены к outbound для внешних HTTPS интеграций.

Оба приложения работают UID 10001, root filesystem read-only, capabilities
сброшены, no-new-privileges, tmpfs для временных файлов. PostgreSQL работает под
пользователем postgres; на Alpine UID 70. Named volume наследует ownership образа.
API ограничен 512 MiB / 1 CPU, Worker 2 GiB / 2 CPU / tmpfs 4 GiB, БД 768 MiB / 1 CPU.
Каждый контейнер ограничен 128 PID. Логи ротируются 10 MiB × 3.

API ждёт healthy PostgreSQL; Worker ждёт healthy API, чтобы bootstrap завершился.
Миграции применяются SQLx с advisory lock. Worker readiness heartbeat обновляет
файл только при успешной связи с БД и работе scheduler. API ready проверяет БД.
restart unless-stopped восстанавливает сервисы при работающем Docker после reboot.
Настройку автозапуска Docker выполняет администратор хоста.

Dockerfile API собирает React в Node stage и Rust в builder stage. Runtime Debian
содержит только бинарник, CA, curl для healthcheck и SPA. Worker дополнительно
содержит Trivy 0.76.2 из официального GHCR. Для воспроизводимости релиза закрепите
проверенные digests базовых образов в вашем процессе поставки.
Cargo.lock должен включаться в сборку с --locked; package-lock обязателен для npm ci.
Фактическое состояние сборки и lockfiles смотрите в implementation-status.

Production: HTTPS reverse proxy, APP_ENV=production, PUBLIC_BASE_URL с точным
origin. Внешний HTTP порт ограничьте loopback/firewall. Не передавайте auth через
публичный HTTP. Приложение не доверяет X-Forwarded-For для ограничения входа.
Текущий limiter общий на API-процесс: 600 req/min и 15 login/min; при необходимости
добавьте per-IP limiter на proxy. Логи не должны содержать Cookie/Authorization.

S3 extra_hosts добавляется только отдельным сгенерированным override.
Для CA используйте read-only config/certs. Включение discovery не требует
Docker socket и не даёт Worker право менять инфраструктуру.

Безопасное обновление RizenVuln: backup PostgreSQL, review migrations,
сборка новых собственных образов, `docker compose up -d`. Не удаляйте volumes.
Откат бинарника возможен только при совместимой схеме; down migration не предоставляется.
