# Фактическое состояние реализации

Дата обновления: 2026-11-15. **Проект ещё не прошёл полную эксплуатационную приёмку.**
Сборка, автоматические проверки и изолированные API/PostgreSQL/браузерные сценарии
описаны в последних разделах ниже. Ранние таблицы отражают исторические ограничения
среды 2026-11-13 и не являются текущими результатами. Внешние интеграции и реальный
Trivy требуют отдельной приёмки. Матрица покрытия: [testing.md](testing.md).

## Создано

- Единый Rust workspace: apps/api, apps/worker; crates/core, config, database,
  auth, integrations, scanner. Интеграции объединены вместо 17 мелких crates.
- Cargo.lock с реально разрешёнными зависимостями. Rust stable 1.100.0.
- PostgreSQL: 20 требуемых таблиц, UUID/FK/unique/indexes, две SQLx migrations.
- Durable jobs: SKIP LOCKED, lease token, heartbeat, bounded retries, восстановление
  истёкшей аренды, отложенный retry по GitHub rate limit; exhausted jobs FAILED.
- API: все минимальные коллекции и дополнения; auth, projects/images/repos create,
  scan enqueue, remediation history, approvals, SBOM download/packages/compare,
  Harbor project selection, Telegram test, notification rules, admin user create
  и password reset с отзывом сессий. OpenAPI JSON и единая оболочка ошибок.
- Auth: Argon2id, opaque session token, HttpOnly/SameSite cookie, Secure в HTTPS,
  CSRF token+Origin, admin/viewer, ограничение API/login, аудит административных действий.
- Worker: scheduler, bounded concurrency, graceful stop, readiness heartbeat.
- OCI: Docker Hub / GHCR / public registries, auth challenge, tags pagination,
  manifest/digest validation, architecture selection. Проверенное скачивание blobs
  в локальный OCI layout без foreign URLs/daemon/run; лимит размера/числа blobs.
- Trivy: фиксированные аргументы, local OCI input, offline-scan для идентификации
  зависимостей, JSON/CycloneDX/SPDX, timeouts/env_clear, digest и scanner/DB metadata.
  CVE normalization/dedup, сохранение исторических scans/findings.
- Harbor: API v2 projects/repos/artifacts/tags/digest, pagination/retry/read-only,
  готовые scan reports, additions SBOM с fallback на OCI referrers.
- GitHub: releases/tags/advisories/optional commits, ETag releases, rate limits,
  draft/prerelease exclusion для stable-release notifications.
- S3: подписанный SigV4 PUT, private CA, очереди загрузки, локальная копия JSON.
- Telegram: durable outbox/dedup/retry, правила включения событий, test action.
- CISA KEV и FIRST EPSS enrichment; отдельные KEV notifications.
- Update advisor: SemVer, stable-only, digest equality/mutable changes, major warning,
  history, approval/test/production states; никаких автоматических обновлений.
- Read-only Docker mTLS/Kubernetes token+CA discovery; без socket mount.
  Docker config ImageID не подменяет manifest RepoDigest.
- React/TypeScript: 13 разделов, темы, responsive layout, 5 графиков, реальные API
  queries/mutations, таблицы/поиск/пагинация, CVE project/image/environment/severity/
  status/fix/KEV/EPSS filters, формы источников, SBOM packages/diff, admin forms.
- Multi-stage Dockerfile API/Worker, Compose с тремя сервисами, healthchecks,
  named volumes/internal DB network, resource limits/read-only/non-root/log rotation.
- .env.example, exclusive secret generator (0600), S3 hosts/override scripts,
  Kubernetes RBAC manifest, GitLab CI, AGENTS.md, README и документация на русском.

## Проверки и их реальные результаты

| Проверка | Результат |
|---|---|
| cargo fmt --all -- --check | Успешно после форматирования |
| cargo clippy --workspace --all-targets -- -D warnings | Успешно, замечания исправлены |
| cargo build --workspace --locked | Успешно (debug; release Docker build не проверен) |
| cargo test --workspace | НЕ прошёл: 19 passed, 8 failed при TCP bind mock server, 2 ignored PostgreSQL tests |
| Отдельный запуск без восьми socket-dependent tests | 19 passed, 2 ignored DB tests, 8 filtered out; исключённые проверки не объявляются пройденными |
| Python unittest (hosts/config/OpenAPI/schema contract) | 9 passed |
| sh -n для четырёх shell scripts | Успешно |
| TS/TSX parser | 13 файлов синтаксически разобраны Babel; это НЕ tsc/build/test |
| npm ci | Не выполнен успешно: отсутствует package-lock.json |
| npm install / metadata offline | Нет @tanstack/react-query в локальном cache; npm registry DNS EAI_AGAIN |
| npm run build | Не выполнен: tsc не установлен |
| npm run test -- --run | Не выполнен: vitest не установлен |
| Compose config с .env.example | Успешно; основной файл без extra_hosts и сгенерированный override с временной IPv6 fixture отдельно валидны |
| docker compose build / up -d / ps | Все заблокированы permission denied / operation not permitted для Docker socket |
| Реальные Harbor/GitHub/S3/Telegram/Trivy/Discovery подключения | НЕ проверены с реальными credentials/сервисами |

Cargo test failure: wiremock не может открыть loopback TCP port:
`Failed to bind an OS port for a mock server: Operation not permitted`.
Все восемь mock tests оставлены обычными тестами, не скрыты ignore/auto-skip.
Два DB-теста явно ignored, запускаются отдельно только в выделенной тестовой БД:
очередь/dedup и cookie+CSRF+RBAC+logout workflow.

Первоначально toolchain был неполным; позднее стал доступен и Rust проверки
выполнены реально. Состояние нельзя оценивать по ранним сообщениям об отсутствии rustc.
Frontend registry DNS и Docker permissions остались блокирующими.

Compose проверен командой:

```bash
RIZENVULN_ENV_FILE=.env.example docker compose --env-file .env.example config -q
```

Настоящий .env не генерировался без email владельца. Контейнеры не созданы,
миграции не применялись к живой БД, /etc/hosts не изменён. Данные/сервисы пользователя
не удалялись. Резервные копии hosts проверялись только на временном тестовом файле.

## Не реализовано / функциональные ограничения

1. Нет end-to-end приёмки и рабочей демонстрации с PostgreSQL/Trivy/браузером.
   Frontend package-lock отсутствует: его нельзя выдумать вместо npm resolution.
2. S3/Docker/Kubernetes адаптеры написаны на Reqwest/HMAC REST, а не на зрелых
   специализированных SDK; нужна проверка совместимости и дополнительное ревью.
   S3 multipart/session token/assume-role не реализованы; Docker API фиксирован v1.45.
3. Advisor выбирает новые SemVer tags и обнаруживает mutable digest. Calendar/custom
   schemes консервативно UNKNOWN; пользовательских tag policies нет. Нет анализа
   candidate scan для доказательства SECURITY_FIX_AVAILABLE и автоматической
   корреляции GitHub release ↔ image. Наличие версии в registry не доказывает deployment.
   Без discovery текущая registry observation не является подтверждённой production версией.
4. GitHub releases ограничены 100, commits 30; tags/advisories до 10000. Selected branch
   запрашивается при track_commits=true. Отдельные вкладки releases/advisories отсутствуют:
   данные видны как JSON в details. Ошибка advisory endpoint блокирует весь snapshot.
5. Harbor: только поддержанные report schemas и OCI 1.1 referrers. Есть ограничения
   vendor/version совместимости; unsupported report не считается чистым scan.
   Нет отдельной таблицы статуса отсутствующего SBOM: он хранится в image metadata.
6. Discovery конфигурируется одним Docker и одним Kubernetes endpoint, без SDK/kubeconfig.
   Environment задаётся явно конфигурацией источника, по умолчанию unknown.
   UI mapping deployment→project/server/environment пока нет, stale records сохраняются.
7. Notification rules включают/выключают типы событий; гибкие thresholds/conditions,
   расписания и отдельная политика уведомления об изменении EPSS отсутствуют.
   Telegram at least once: после uncertain delivery возможен дубликат.
8. Нет удаления/редактирования источников/проектов, удаления пользователя/смены роли,
   MFA, самостоятельного password recovery. Admin create/reset реализованы.
9. Нет UI audit log/history timeline, retry FAILED job, полного streaming export,
   retention/GC/автоматического backup. JSON export UI ограничен текущей страницей.
10. Детальная карточка проекта со связанными сущностями заменена общими таблицами
    и project filters. Пригодность/доступность frontend в браузере ещё не проверена.
11. Ограничение HTTP/login общее на процесс, не per-IP; несколько Worker instances
    не имеют общей квоты scan concurrency. Запускать один Worker.
12. Файл scan report и нормализованные findings сохраняются отдельными транзакциями;
    при crash возможен частичный scan/artifact set. Прерванные RUNNING scans старше
    двух часов помечаются FAILED. Полная atomic completion/outbox требует доработки.
13. OpenAPI поддерживается отдельным JSON, DTO requests типизированы, но многие read
    responses динамические JSON. Полная генерация frontend типов из OpenAPI отсутствует.
14. Для untrusted image parsing требуется отдельное эксплуатационное security review.
    Тесты S3 проверяют HMAC primitives и форму signed PUT, не заменяют проверку AWS
    SigV4 interoperability. Trivy binary из контейнера здесь не запускался.

## Следующие шаги в порядке выполнения

1. На машине с npm registry: `cd frontend && npm install`, сохранить настоящий
   package-lock, выполнить npm ci/build/test и исправить type/runtime failures.
2. В среде с loopback socket permission выполнить cargo test --workspace полностью.
   Создать отдельную тестовую PostgreSQL БД, задать TEST_DATABASE_URL, запустить
   ignored DB tests и API auth workflow; проверить миграции/queue concurrency/lease loss.
3. С разрешённым доступом к Docker выполнить compose config/build/up/ps, healthchecks,
   войти в Dashboard, добавить проект/GitHub/публичный image; проверить Trivy OCI
   directory input, CVE и оба SBOM formats.
4. Проверить Harbor конкретной версии, S3 с TLS/CA, Telegram и discovery с настоящими
   минимальными credentials. Не публиковать их в отчётах. Проверить notification dedup.
5. Исправить перечисленные функциональные пробелы и atomic completion. Добавить
   regression fixtures и meaningful integration coverage; повторить security review.
6. Только после выполнения 20 критериев готовности изменить статус проекта.

## Проверка готовности к развёртыванию 2026-11-15

- Установлены Docker Compose 2.40.3, Rust 1.100.0, Node.js 22.23.1, npm 9.2.0, Python 3.
- На разделе проекта свободно 374 GiB.
- Compose config -q успешно проверен с .env.example и временным проверочным значением пароля; реальные секреты не создавались.
- cargo fmt и cargo clippy --workspace --all-targets -- -D warnings прошли.
- Python unittest: 9 тестов прошли.
- cargo test --workspace не прошёл: 8 mock HTTP тестов integrations не могут открыть локальный порт (Operation not permitted). Тесты БД требуют отдельной TEST_DATABASE_URL и пропущены; полный прогон остановлен на integrations.
- Попытка npm install с cache в /tmp не удалась: EAI_AGAIN registry.npmjs.org. Package-lock не создан, frontend build/test не выполнены.
- Docker API недоступен сессии: permission denied для /var/run/docker.sock. Образы не скачаны, compose build/up и healthchecks не выполнены.
- .env отсутствует. Для инициализации нужен email администратора: scripts/init-env.sh --email <email>. Production также требует реальный HTTPS PUBLIC_BASE_URL и внешний TLS proxy.
- Для завершения нужен доступ к npm registry и Docker daemon из среды выполнения. Права socket, группы пользователя и инфраструктура не изменялись.

### Исправление Compose tmpfs

После сообщения пользователя об ошибке invalid mount path gid=70 исправлено YAML quoting всех tmpfs API, Worker и PostgreSQL: каждая mount specification теперь является одной строкой. Compose config -q проходит. Повторный запуск контейнеров из этой сессии не выполнялся; требуется compose up -d на хосте. Пользователь сообщил об успешной сборке обоих образов до ошибки создания PostgreSQL.

### Исправление авторизации 2026-11-15

- В работающем Compose воспроизведён POST /api/v1/auth/login → 401 «Требуется вход» даже с данными из .env: guard сравнивал полный путь с URI, из которого Axum nest уже удалил /api/v1. Для login и исключения viewer logout теперь используется OriginalUri. Проверки Origin, CSRF и ролей сохранены.
- Добавлен регрессионный тест без БД: login без сессии доходит до проверки Origin, защищённый маршрут продолжает возвращать 401.
- cargo fmt --all -- --check, cargo clippy --workspace --all-targets -- -D warnings и cargo test --workspace прошли (два DB-теста по умолчанию ignored). Дополнительно auth_workflow с --ignored прошёл на отдельной временной PostgreSQL БД: login, cookie, CSRF, RBAC, viewer/admin logout. Временная БД удалена.
- npm ci, npm run build и npm run test -- --run прошли, 10 frontend-тестов. npm сообщил о трёх уязвимостях зависимостей (1 moderate, 2 critical); обновление зависимостей в это исправление не входит. Сборка также предупреждает о JS chunk больше 500 kB.
- Прежние ограничения доступа к Docker/npm/loopback выше относятся к предыдущей проверке: сейчас Compose доступен, API/Worker/PostgreSQL запущены. Секреты не изменялись и не выводились; история сканирований сохранена.
- API пересобран через docker compose build и пересоздан через docker compose up -d --no-deps rizenvuln-api. На работающем API проверены данные из .env: login 200, /auth/me 200 с ролью admin, logout 200, отозванная сессия 401, /health/ready 200. Все три сервиса healthy. Проверка HTTP выполнена внутри API-контейнера; браузерный вход отдельно не проверялся. Для текущего PUBLIC_BASE_URL открывать http://localhost:8080 (другой Origin будет отклонён).

### Расширение автотестов и GitHub Actions 2026-11-15

- Полный `./scripts/check.sh` прошёл: fmt, Clippy с -D warnings, 40 обычных Rust-тестов, 15 PostgreSQL integration tests (запущены явно, без пропуска), 13 Vitest, 9 Python unittest и 2 Chromium/Playwright сценария. Всего 79 тестов; subprocess-варианты конфигурации и параметризованные сценарии внутри них отдельно не суммируются. Сборка frontend и Compose config также прошли.
- Тестовый runner создаёт собственную временную PostgreSQL в отдельном Compose project с данными в tmpfs и удаляет её после успеха/ошибки. API/DB/Worker fixtures работают в отдельных схемах, включая прежние DB tests; разрешён только TEST_DATABASE_URL с именем БД rvtest_*. Рабочие .env, БД, volumes и контейнеры не используются.
- Покрыты auth/session/password reset/Origin/CSRF/RBAC, все документированные закрытые API routes без сессии, source creation/validation/lists, CVE latest-successful scan/filter/history, SBOM/diff, approval, notifications/dedup, metrics/health, invalid/oversized requests, queue concurrency/lease fencing/retry/exhaustion, scheduler и scan persistence. Добавлены проверки конфигурации в subprocess и HTTP redirect/retry/SSRF/error cases.
- Scanner проверяется executable fixture: протокол трёх форматов, version, nonzero exit, malformed/incomplete JSON, timeout, удаление временных файлов, ограничение документа. Это не реальный Trivy и не проверка его CVE DB.
- Chromium работает с настоящим временным API/PostgreSQL: login, создание проекта/образа/GitHub source, обновление страницы, все разделы, создание viewer и смена пароля, ограничения viewer и logout. Worker в браузерной фикстуре не запускается: внешние источники не опрашиваются.
- Найдены и исправлены три ошибки: SPA reload возвращал 404 и JSON вместо index.html; повторная запись artifact ставила S3 job для UUID, отклонённого ON CONFLICT; frontend принимал невалидный JSON успешного ответа за данные. Все три сценария имеют регрессионные тесты.
- .gitlab-ci.yml удалён. .github/workflows/test.yml настроен на push/pull_request/manual: Rust/Python/DB/Chromium, frontend и сборка Compose images. Локальная проверка YAML выполнена; результат запуска на GitHub фиксируется отдельно и не подменяется локальным успехом.
- Подробная матрица и команды: docs/testing.md. 100% покрытия и гарантия отсутствия ошибок не заявляются. Внешние Harbor/S3/Telegram/Docker/Kubernetes/GitHub/KEV/EPSS, настоящий Trivy, длительная нагрузка и аварии инфраструктуры требуют отдельной приёмки. Предупреждения npm audit и размера JS chunk из предыдущей проверки сохраняются.
- Рабочие сервисы оставлены на прежних образах: новые изменения приложения из этого раздела требуют последующей пересборки/обновления Compose. Во время тестов рабочая история сканирований не изменялась.
