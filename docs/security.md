# Модель безопасности

Argon2id с независимой случайной солью; opaque session token 256 bit.
В БД только SHA-256(secret || separator || token). SESSION_SECRET не хранится в БД.
Сессия 12 часов, logout удаляет текущую, ротация секрета отзывает все.
Cookie HttpOnly/SameSite=Strict, Secure при HTTPS. Для локального HTTP development
Secure отсутствует. Production config без HTTPS отклоняется.

Mutating запросы (кроме собственного logout) требуют admin. Каждый mutating запрос требует точный Origin и X-CSRF-Token, хеш которого
связан с сессией. Login также требует Origin. Viewer имеет read-only REST доступ.
Токен CSRF хранится frontend в sessionStorage (не является session credential).
Пароли хешируются в spawn_blocking. Общий limiter ограничивает API/login; per-IP
лимитер следует настраивать на reverse proxy. MFA и самостоятельного восстановления через email пока нет. Admin может создать пользователя и сменить пароль с отзывом сессий.

SQL только с bind parameters; динамические table names задаются статическим кодом,
sort key передаётся параметром JSON field, порядок выбирается из ASC/DESC.
Входящие body ограничены 1 MiB. React экранирует текст, dangerouslySetInnerHTML нет.
CSP запрещает сторонние scripts/objects/framing, выставлены nosniff/referrer policy.
Валидация URL ограничивает scheme/credentials/origin. Все DNS-адреса должны пройти
IP policy; разрешённые адреса закрепляются в клиенте, env proxies отключены.
Запрещены loopback/metadata/link-local, включая IPv4-mapped IPv6. Внутренние адреса
доступны только явно заданным Harbor/S3/Discovery endpoints. Автоматических
redirect нет; OCI blob CDN redirects повторно проверяются без передачи credentials.

Worker скачивает только registry API blobs по digest, игнорирует чужие layer URLs,
проверяет SHA-256/размеры, ограничивает скачивание 1 GiB и 256 blobs. Проверяются
manifest digest и SBOM integrity. Trivy работает только с локальным OCI directory,
фиксированными аргументами, env_clear, timeout/kill_on_drop, non-root, read-only FS,
ограничениями CPU/RAM/PID/tmpfs. Контейнеры анализируемых образов не запускаются.
Для защиты от ошибок стороннего сканера дополнительно ограничьте egress Worker
средствами хоста. Trivy получает свою DB с собственных upstream endpoints.

Аудит: login, создание проектов/источников, scan enqueue, выбор Harbor,
remediation, approvals, Telegram test. Audit хранится в той же БД и не защищён от
изменения самим администратором БД. Нет подписанного append-only внешнего аудита.
Ошибки внешних запросов в job/API санитизированы, чтобы исключить URL с bot token.
JSON-логи tracing совместимы с Loki; не включайте подробные debug HTTP логи с headers.

Discovery — только HTTPS GET. Docker требует mTLS; Kubernetes — read-only token/CA.
Наличие image в Harbor не означает deployment. Docker ImageID не считается registry
manifest digest; читаются RepoDigests и сравниваются repository names.
Kubernetes ambiguous runtime-only IDs остаются без digest вместо догадки.

Секреты только в окружении/readonly TLS files, .env chmod 0600 и gitignore.
Будущий Vault provider предусмотрен контрактом, но сейчас не реализован.
Текущая версия требует дополнительного ревью и выполнения полного набора тестов
перед эксплуатацией; известные пробелы перечислены в implementation-status.
