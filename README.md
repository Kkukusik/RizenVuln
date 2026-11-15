# RizenVuln

Персональный центр мониторинга безопасности инфраструктуры: Rust API и Worker,
PostgreSQL, React Dashboard, Trivy, Harbor, GitHub, OCI, S3 и Telegram.
Интерфейс на русском языке, тёмная/светлая тема. Приложение только наблюдает:
не развёртывает версии, не перезапускает контейнеры, не меняет Harbor.

**Статус: начальная реализация, не прошедшая приёмку для эксплуатации.**
Точные проверки и пробелы: [implementation-status](docs/implementation-status.md).
Наличие кода адаптера не означает проверенное подключение к реальному сервису.

## Архитектура и структура

```text
apps/api/              Axum REST, сессии, CSRF, SPA, health, metrics
apps/worker/           Планировщик и обработчики PostgreSQL-очереди
crates/core/           Версии, digest, CVE, SBOM, SSRF IP policy
crates/config/         Конфигурация, SecretProvider
crates/database/       SQLx, миграции, lease/retry/dedup
crates/auth/           Argon2id и случайные токены
crates/integrations/   Harbor, GitHub, OCI, S3, Telegram, KEV/EPSS, discovery
crates/scanner/        Ограниченное выполнение Trivy для локального OCI layout
frontend/              React + TypeScript + Vite + Tailwind + TanStack Query
migrations/            PostgreSQL schema (20 таблиц)
docker/                Multi-stage API/Worker Dockerfile
config/certs/          Дополнительные CA / read-only TLS-файлы
scripts/               Настройка окружения, S3 hosts, проверки
tests/                Тесты конфигурационных скриптов
 docs/                 Документация, OpenAPI, статус реализации
```

Близкие интеграции объединены в один crate: отдельный crate для каждого HTTP
адаптера усложнил бы workspace без изоляции процессов. API и Worker разделены,
бизнес-правила не зависят от SQL/HTTP. См. [архитектуру](docs/architecture.md).

## Требования

Linux, Docker Engine и Compose v2; для сборки доступ к crates.io, npm и реестрам
базовых образов. Рекомендуется 4 CPU, 8 GiB RAM и 30 GiB диска плюс резерв для
PostgreSQL и Trivy cache. На одну проверку выделяется до 1 GiB сжатых OCI blobs;
промежуточные OCI layout ограничены tmpfs Worker 4 GiB.
Для разработки: Rust stable, Node.js 22.12+, npm, Python 3.10+.

## Первоначальный запуск

```bash
./scripts/init-env.sh --email YOUR_ADMIN_EMAIL
# Откройте .env локальным редактором. Скрипт не выводит секреты.
# Проверьте PUBLIC_BASE_URL и параметры подключений.
docker compose config -q
docker compose build
docker compose up -d
docker compose ps
curl --fail http://localhost:8080/health/ready
```

Скрипт создаёт `.env` с правами 0600 и случайными паролями, не перезаписывая
существующий файл. `YOUR_ADMIN_EMAIL` замените вашим email. Вход выполняется
с `ADMIN_EMAIL` / `ADMIN_PASSWORD` из локального `.env`. Первый admin создаётся
автоматически, только если в БД ещё нет admin. Повторный запуск не сбрасывает пароль.
Файл `.env` нельзя коммитить или включать в резервные копии без защиты.

Веб-интерфейс: **http://localhost:8080**. `HTTP_PORT` меняет опубликованный порт,
`PUBLIC_BASE_URL` должен содержать фактический адрес браузера. По умолчанию порт
доступен только на loopback хоста. Для production настройте внешний reverse proxy,
`APP_ENV=production`, `PUBLIC_BASE_URL=https://<ваш-домен>`. TLS завершается на proxy,
а API ставит Secure cookies. В development HTTP cookie остаётся HttpOnly/SameSite
без Secure, чтобы локальный HTTP-вход был возможен.

## Работа с Dashboard

1. В разделе «Проекты» создайте проект.
2. В «Образы» добавьте, например, `nginx:stable-alpine`, выбрав проект.
3. Worker проверит manifest и digest, скачает blobs с проверкой SHA-256 и сформирует
   локальный OCI layout. Trivy анализирует каталог OCI; образ никогда не запускается.
4. Статусы/ошибки видны в таблицах. «Уязвимости» содержит фильтры severity, project,
   fix available, status, KEV; API также поддерживает min_epss.
5. «Исправления»: откройте запись и измените статус. История сохраняется в БД.
6. «SBOM Explorer»: откройте CycloneDX/SPDX документ для просмотра пакетов,
   поиска по имени/лицензии, скачивания; сравните два результата на текущей странице.
7. «Обновления»: версии сравниваются по SemVer, mutable tags — по digest.
   Одобрение не устанавливает версию и не подтверждает безопасность.

Нулевой счётчик CVE не равен подтверждению безопасности. Dashboard отдельно
показывает образы без свежего успешного сканирования. Сохраняются старые результаты.

## GitHub

В «GitHub» выберите проект, добавьте `https://github.com/goharbor/harbor`, ветку и
при необходимости мониторинг коммитов. Публичный доступ возможен без токена.
Приватный репозиторий требует `GITHUB_TOKEN` с минимальными правами чтения.
Releases, tags, advisories и commits доступны в подробностях записи.
Prerelease и обычный tag не считаются стабильным release. [Подробнее](docs/github.md).

## Harbor

Задайте `HARBOR_ENABLED=true`, `HARBOR_URL` (HTTPS), `HARBOR_USERNAME`,
`HARBOR_PASSWORD`, при необходимости `HARBOR_CA_FILE=/app/certs/harbor-ca.pem`.
Пересоздайте API/Worker командой `docker compose up -d`. В «Интеграции» нажмите
«Мониторинг Harbor» и выберите нужный проект. Импортируются только выбранные проекты.
Готовые vulnerability reports читаются без запуска сканирования Harbor.
SBOM: Harbor additions API, затем OCI referrers fallback; отсутствие явно помечается.
[Подробности и ограничения](docs/harbor.md).

## S3

Задайте `S3_ENABLED=true`, endpoint/region/bucket/access/secret. Bucket создаёт
администратор S3 заранее; приложение не меняет политики. Для частного CA добавьте
сертификат в `config/certs/`, задайте `S3_CA_FILE=/app/certs/s3-ca.pem`.
TLS всегда проверяется. [Подробности](docs/s3.md).

Если домен требует явного IP, задайте реальные `S3_HOSTNAME` / `S3_HOST_IP`:

```bash
./scripts/compose-s3.sh
docker compose -f docker-compose.yml -f docker-compose.s3.yml up -d
# Отдельно, администратором сервера, только при необходимости:
sudo ./scripts/configure-s3-hosts.sh
```

При пустых hostname/IP скрипты ничего не меняют. Основной Compose не содержит
фиктивных extra_hosts. Скрипт hosts делает backup, обновляет только свою запись,
отказывается менять чужой конфликтующий mapping и проверяет resolver.

## Telegram

Создайте bot и задайте `TELEGRAM_ENABLED=true`, `TELEGRAM_BOT_TOKEN`,
`TELEGRAM_CHAT_ID`. Секреты остаются в `.env`. В «Уведомления» доступна тестовая
отправка. Уведомления хранятся в БД и отправляются через очередь с retry/dedup.
Telegram не поддерживает idempotency key: при потере ответа после приёма сообщения
внешним сервисом возможна повторная доставка. Обычные повторные сканы не создают
повтор того же события.

## Проверки

```bash
./scripts/check.sh
# Только для отдельной пустой тестовой БД, не production:
TEST_DATABASE_URL='postgres://...' cargo test -p rizenvuln-database -- --ignored
```

HTTP mock tests требуют разрешения открывать loopback TCP-порты.
Frontend использует `npm ci`, после создания настоящего `package-lock.json`:
если файл отсутствует, сначала на машине с сетью выполните `cd frontend && npm install`.
Состояние lockfiles и выполненных проверок указано в implementation-status.

## Диагностика

```bash
docker compose logs --tail=100 rizenvuln-api rizenvuln-worker
docker compose ps
curl --fail http://localhost:8080/health/live
curl --fail http://localhost:8080/health/ready
```

`/metrics` требует Bearer `METRICS_TOKEN`; не передавайте значение в общедоступных
командах/логах. Список заданий и последняя ошибка доступны admin через API.
[Диагностика](docs/troubleshooting.md), [API](docs/api.md), [безопасность](docs/security.md).

## Backup / restore PostgreSQL

Резервные копии содержат данные инфраструктуры и хеши паролей. Ограничьте доступ.

```bash
umask 077
docker compose exec -T rizenvuln-postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > rizenvuln.dump
```

Восстанавливайте в отдельную пустую БД после остановки только API/Worker RizenVuln:

```bash
docker compose stop rizenvuln-api rizenvuln-worker
# Целевая БД должна быть пустой; команда не удаляет существующие объекты:
docker compose exec -T rizenvuln-postgres sh -c 'pg_restore --exit-on-error --no-owner -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < rizenvuln.dump
docker compose up -d rizenvuln-api rizenvuln-worker
```

Не выполняйте `down -v`. Сохраняйте `.env` отдельно в защищённом хранилище и
включайте резервирование S3 bucket. [Развёртывание](docs/deployment.md).

В «Настройки» admin может создавать пользователей с ролью viewer/admin и менять
пароли с отзывом всех сессий. «Уведомления» позволяет отключать отдельные типы
событий; фильтрация по произвольным условиям пока отсутствует.
