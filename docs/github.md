# GitHub

Добавление через UI или POST /api/v1/repositories с project_id/reference/branch/
track_commits. Разрешены github.com URL либо owner/repository, без произвольных URL.
Запросы идут только в api.github.com, API version 2022-11-28, User-Agent RizenVuln.

Поддерживаются releases, tags, security advisories, выбранная ветка при commits
monitoring. Stable-release notification исключает draft и prerelease. Git tag не
превращается в release. Tags/advisories имеют ограниченную пагинацию до 10000
элементов; releases сейчас ограничены первой страницей из 100, commits — 30.
Сохранённые данные доступны в подробностях репозитория. UI отдельных вкладок
release/advisory пока не реализован.

Releases поддерживают ETag/If-None-Match. 304 сохраняет прежние releases, при этом
остальные endpoints обновляются: ETag одного endpoint не замораживает весь repo.
HTTP 403/429 отображаются как ошибка интеграции с rate limit reset без токена.
Повторы регулируются очередью; Retry-After / x-ratelimit-reset задают отложенный run_at, без блокирующего ожидания Worker. GITHUB_TOKEN нужен для приватных repos и расширенных
лимитов. Права на advisories зависят от GitHub и токена; ошибка не маскируется
пустым списком и может помешать синхронизации всего repository snapshot.

Связь repository → container image пока не задаётся отдельной формой. Добавляйте
оба источника в один проект. Уведомление о новом stable release dedup по repo/tag;
начальная синхронизация также может отправить последнее stable release.
