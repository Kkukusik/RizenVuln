# Диагностика

## API не стартует
Проверьте обязательные секреты и DATABASE_URL. Не публикуйте .env и connection URL
в issue. При APP_ENV=production нужен HTTPS PUBLIC_BASE_URL. Миграции применяются
при запуске; ошибка миграции не игнорируется. /health/live проверяет процесс,
/health/ready — соединение с БД.

## 403 / CSRF
PUBLIC_BASE_URL должен точно совпадать с Origin браузера (scheme/hostname/port).
localhost и 127.0.0.1 — разные origins. После смены SESSION_SECRET войдите заново.
Не удаляйте sessionStorage CSRF token при активной сессии; при его потере выполните
повторный вход. Приложение не доверяет произвольным forwarded заголовкам.

## OCI/Trivy
Посмотрите images.status, reports и /api/v1/jobs. SCAN_REGISTRY_ALLOWLIST должен
содержать разрешённый администратором registry. Digest manifest проверяется при
скачивании; отказ при mismatch является ожидаемой защитой. SCAN_ARCHITECTURE
должен существовать в index. Большие images могут превысить 1 GiB/max tmpfs.
Private image требует Docker Hub/GHCR credentials. Внешние ошибки намеренно краткие,
чтобы не раскрыть секреты в логах. Повторный scan — кнопка в details образа.

## Harbor / S3 TLS
Проверьте CA file path внутри контейнера, DNS/extra_hosts, срок сертификата и SAN.
Не используйте -k/disable TLS. Для S3 загрузок сравните region и bucket policy.
S3 ERROR не удаляет локальный отчёт. Harbor SBOM UNAVAILABLE означает отсутствие
поддерживаемого artifact/API, а не отсутствие зависимостей.

## Telegram
Bot должен иметь доступ к chat. Состояние очереди/уведомления сохраняется в БД.
Обычные события dedup; после ambiguous network failure Telegram возможен повтор.
Не публикуйте URL Bot API с токеном.

## Ограничения окружения разработки
Docker socket permission denied: действия выполняет администратор через уже
настроенный разрешённый доступ к Docker. Приложению socket не требуется.
Не обходите sandbox и не передавайте sudo password в команды.
Rust toolchain неполный: администратор может выполнить `rustup toolchain install
stable --profile minimal --component rustfmt --component clippy`.
Отсутствует npm lock: в каталоге frontend выполните `npm install` при доступе к npm,
затем `npm ci`, build и tests. Не создавайте искусственные lockfile/integrity.
Mock tests требуют loopback TCP bind; Operation not permitted в wiremock означает
ограничение окружения, а не успешное прохождение теста.

## Ресурсы
Логи: docker compose logs --tail=100. В Compose healthchecks и log rotation уже
настроены. Worker graceful stop 60s, незавершённые jobs восстанавливаются по lease.
Данные хранятся в named volumes; down -v не использовать. Retention отсутствует:
контролируйте рост PostgreSQL, S3 и cache. Backup/restore — README.
