# REST API

Версия /api/v1. OpenAPI: docs/openapi.json и защищённый /api/v1/openapi.json.
Системные /health/live и /health/ready публичны; /metrics требует Bearer METRICS_TOKEN.
Остальные маршруты используют session cookie; login без сессии, но с Origin.

POST auth/login {email,password} возвращает csrf_token и Set-Cookie rv_session.
GET auth/me возвращает id/email/role. POST auth/logout требует CSRF.
Все POST/PATCH требуют X-CSRF-Token и Origin (login возвращает CSRF). Изменение ресурсов требует admin; собственный logout доступен также viewer.
Формат ошибки: {"error":{"code":400,"message":"…"}}; raw external error не отдаётся.

GET dashboard: counts/severity/trend/integrations.
GET projects/images/repositories/vulnerabilities/sbom/deployments/updates/remediation/
reports/notifications/integrations/jobs: {items,total,page,per_page}.
GET settings: только публичные параметры, без секретов.
Пагинация page>=1, per_page=1..100, default25; q поиск, sort/order asc|desc.
Для findings: severity,status,project_id,image_id,environment,fix_available,kev,min_epss.
Другие ресурсы: общие severity/status/project_id, если поле существует.
Findings API показывает последний успешный scan каждого image; history не удаляется.

POST projects {name,description}; POST images {project_id,reference};
POST repositories {project_id,reference,branch,track_commits}.
POST images/{id}/scan → enqueue, не синхронный запуск.
PATCH remediation/{id} {status,note} → изменение+history+audit транзакционно.
GET sbom/{id} → JSON исходного документа.
GET sbom/{id}/packages?q=&page=&per_page= → нормализованные name/version/license/purl.
GET sbom/compare?left=<UUID>&right=<UUID> → added/removed tuples name/version/purl.
POST updates/{id}/approve {environment:"test"|"staging"|"production"} → запись
approval с digest и user, не deployment и не оценка безопасности.
POST notifications/test → очередь тестового Telegram.
GET integrations/harbor/projects → проекты доступные Harbor account.
POST integrations/harbor/monitor {project_id,harbor_project} → выбор проекта.

UI export сохраняет текущую страницу JSON. Полный потоковый экспорт всех данных,
API для удаления/изменения роли пользователя, редактирования произвольных политик, связи
repo/image и автоматического retry failed jobs пока не реализованы.

GET/POST settings/users: список без password hashes / создание {email,password,role}, admin.
POST settings/users/{id}/password {password}: сброс пароля с отзывом всех сессий, admin.
GET/POST notifications/rules: список / {event,enabled}; выключенные события не
создают новые сообщения, уже поставленные задания не отменяются.
