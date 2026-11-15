# Harbor

Задайте HTTPS URL и robot account с минимальными pull/read правами.
HARBOR_ENABLED=true включает адаптер, но не выбирает все проекты автоматически.
Выбор: «Интеграции → Мониторинг Harbor», локальный проект + проект Harbor.
Можно выбрать несколько проектов. Выбор сохраняется в sources.

API v2.0: projects, repositories, artifacts (with_tag), additions/vulnerabilities,
additions/sbom. Projects/repos/artifacts используют page/page_size=100;
не более 1000 страниц на операцию. Repository path double-encoded согласно
контракту Harbor для вложенных repository names. GET retries для HTTP 429/5xx
ограничены тремя попытками; сетевые сбои повторяет PostgreSQL job.

Сохраняются artifact metadata, tags/digest и нормализованные findings из готового
отчёта. Неподдерживаемая структура report не трактуется как отсутствие CVE.
Если additions/sbom отсутствует, используется OCI 1.1 referrers API: выбирается
CycloneDX/SPDX artifact, скачивается blob и проверяется digest. Если версия Harbor
не поддерживает оба способа или SBOM не опубликован, metadata.sbom_status=UNAVAILABLE.
Никаких фиктивных SBOM или выводов о безопасности не формируется.

Адаптер никогда не вызывает POST scan, DELETE artifacts или изменение policies.
Все запросы чтения authenticated по TLS. Внутренние IP разрешены только для
явно настроенного Harbor origin; redirects не передают пароль другому origin.
HARBOR_CA_FILE добавляет доверенный CA без отключения стандартной проверки TLS.

Mock tests проверяют запрос проектов, ошибки 401, кодирование путей.
Совместимость с конкретной версией и реальными credentials не проверена.
Не все vendor-specific варианты scan-report и устаревшие схемы OCI artifacts
поддерживаются; новые ответы должны добавляться через реальные fixtures и тесты.
