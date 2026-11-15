# Конфигурация

Полный перечень — `.env.example`. `.env` читается Docker Compose как env_file,
Rust напрямую читает process environment. Shell source/eval файла не используется.
Для cargo run экспортируйте окружение своим безопасным менеджером окружения.

Обязательны DATABASE_URL, ADMIN_EMAIL, ADMIN_PASSWORD (16+ символов), SESSION_SECRET
(32+ символов). init-env создаёт случайные секреты, согласованные POSTGRES_PASSWORD
и DATABASE_URL. Пароль БД в URL требует percent encoding при ручном редактировании.
SESSION_SECRET меняет хеши токенов: ротация немедленно инвалидирует все сессии.
ADMIN_* bootstrap не сбрасывает существующего пользователя.

APP_ENV=production требует PUBLIC_BASE_URL=https://…; PUBLIC_BASE_URL определяет
CSRF Origin и Secure cookie, не заголовки недоверенного proxy.
APP_PORT — внутренний порт 8080 в Compose, HTTP_PORT — опубликованный порт.
HTTP_BIND=127.0.0.1 по умолчанию. FRONTEND_DIR внутри API image уже задан.

SCAN_INTERVAL_HOURS 1–8760; MAX_CONCURRENT_SCANS 1–8 (на один Worker).
SCAN_ARCHITECTURE=amd64 (можно arm64); сканируется одна платформа index.
MAX_IMAGE_BYTES ограничен максимум 1 GiB, учитывает реально скачанные bytes.
SCAN_REGISTRY_ALLOWLIST перечисляет разрешённые администратором реестры для
локального Trivy scanning; manifest discovery остаётся доступным для публичных OCI.
TRIVY_CACHE_DIR — отдельный named volume. Tmpfiles находятся в tmpfs Worker.
SCAN_ENABLED=false сохраняет discovery, но не считает источник проверенным Trivy.

При включении Harbor/S3/Telegram/Discovery соответствующие обязательные параметры
проверяются при запуске. GitHub token необязателен для public repos.
DOCKERHUB_USERNAME/TOKEN и GHCR_USERNAME/GITHUB_TOKEN используются для registry auth.
Приватные произвольные OCI registries пока не имеют UI/config credentials mapping.

SecretProvider сейчас синхронный EnvironmentSecretProvider. Будущий Vault provider
может реализовать тот же контракт; Vault API и токены сейчас не добавлены.
Не логируйте Config целиком: он намеренно не реализует Debug.

METRICS_TOKEN защищает /metrics. S3_CA_FILE, HARBOR_CA_FILE, DOCKER_CA_FILE,
DOCKER_IDENTITY_FILE, KUBERNETES_CA_FILE — пути внутри контейнера, не хоста.
config/certs монтируется как /app/certs. Дополнительные глобальные доверенные CA
не устанавливаются приложением.
