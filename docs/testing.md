# Автоматические проверки

Полный локальный прогон:

```sh
./scripts/check.sh
```

Нужны Rust из rust-toolchain.toml, Node.js 22, npm, Python 3, Docker Compose.
Скрипт ставит npm-зависимости и Chromium для Playwright. На минимальном Linux
понадобятся системные библиотеки Chromium; на CI их устанавливает
`npx playwright install --with-deps chromium`. Пользовательская инфраструктура
скриптами не настраивается.

Отдельные проверки:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 -m unittest discover -s tests -p 'test_*.py'
(cd frontend && npm ci && npm run build && npm run test -- --run)
python3 scripts/test-integration.py
# Дополнительно настоящий браузер + API + PostgreSQL:
(cd frontend && npx playwright install chromium)
python3 scripts/test-integration.py --browser
```

Обычный cargo test явно пропускает тесты PostgreSQL. Скрипт интеграционных тестов
обязательно запускает их с `--ignored`, а не считает пропуск успехом.
Config environment_probe — вспомогательный subprocess-тест; основная проверка
configuration_policy запускает его с разными изолированными окружениями.

## Изоляция

Каждый запуск создаёт отдельный Compose project `rvtest-*`, временную PostgreSQL
с именем БД `rvtest_*`, случайным паролем и данными в tmpfs. После тестов, включая
ошибки проверок, удаляются только ресурсы этого тестового Compose project.
Основной docker-compose.yml, рабочие API/Worker/PostgreSQL, .env и volumes
не используются. Дополнительные API/DB/Worker-тесты создают отдельные схемы.
Защитная проверка TestDatabase запрещает подключаться к БД без префикса rvtest_.
Тестовые пароли не сохраняются в репозитории; Compose-конфигурация имеет 0600.

Браузерный прогон собирает frontend и API, запускает временный API на свободном
локальном порту и входит с одноразовым паролем. Рабочий Worker не подключается
к этой БД, поэтому добавленные источники не вызывают внешних запросов.
Playwright traces отключены: они могут сохранять ввод пароля. Снимки ошибок и
служебные test-results исключены из Git.

## Матрица сценариев

| Область | Автоматические проверки |
|---|---|
| Авторизация | Правильный/неправильный пароль, неизвестный пользователь, Origin, CSRF, cookie, logout, expiry, отзыв сессий, rate limit, bootstrap без сброса пароля |
| Права | Admin/viewer, закрытые маршруты, запрет viewer mutations и списка пользователей, выход viewer |
| API | Создание проектов/образов/GitHub, canonical references, очередь сканов, dedup, списки, пагинация, поиск, validation, duplicate/404, JSON errors, security headers |
| Уязвимости | Последний успешный scan, исключение старых/FAILED результатов, severity/fix/KEV/EPSS/project/image/environment filters, изменение статуса и история |
| SBOM | CycloneDX/SPDX, licenses/purl, список без тяжёлого document, получение JSON, поиск пакетов, diff, отсутствующий документ |
| Обновления | SemVer/prerelease/major/mutable digest, stable selection, идемпотентное одобрение версии |
| Очередь | Конкурентные enqueue/claim, heartbeat, expired lease, stale worker fencing, retry delay, terminal failure, повторное задание после completion |
| Уведомления | Rules, конкурентная дедупликация и создание одного outbox job |
| Worker | Расписание, dedup due sources, пропуск свежих и Harbor sources, зависшие scans, идемпотентная очередь S3 artifacts, сохранение решений и повторное открытие FIXED/PENDING_VERIFICATION при обнаружении CVE |
| Scanner | Протокол запуска с executable fixture, три JSON формата, version, timeout/nonzero exit, invalid/incomplete JSON, очистка временных файлов, предел 64 MiB, запрет нелокального input |
| HTTP адаптеров | Существующие Harbor/GitHub/OCI/S3 mocks плюс redirect refusal, retry 429/503, отсутствие retry 403, invalid/oversized response, SSRF/metadata/cross-origin |
| Конфигурация | Отсутствующие/фиктивные секреты, HTTPS production, URL credentials, интервалы и границы concurrency, обязательные настройки включённых интеграций; отдельные subprocess без env races |
| Интерфейс | Vitest: API/CSRF/errors/forms/filters/table/theme. Chromium: вход, создание проекта и источников, все разделы меню, reload сессии, создание viewer/смена пароля, права viewer, logout и неверный пароль |

## GitHub Actions

`.github/workflows/test.yml` запускается при push, pull_request и вручную.
Jobs: Rust/Python/изолированные PostgreSQL+Chromium сценарии, frontend build/unit,
Compose validation и сборка обоих образов. GitLab CI удалён.

## Практические границы

Это набор регрессионных и интеграционных проверок, а не доказательство отсутствия
всех ошибок. Не заявляются 100% покрытия кода, длительная нагрузочная приёмка,
проверки дискового переполнения/сетевых разделений или падения PostgreSQL.
Executable fixture проверяет взаимодействие со Scanner, но не заменяет реальный
Trivy с обновлением vulnerability DB и анализом OCI. Нужны отдельные проверки
на настоящих Harbor, S3, Telegram, Docker mTLS, Kubernetes, GitHub и KEV/EPSS.
Mock tests не подтверждают совместимость со всеми версиями этих сервисов.
