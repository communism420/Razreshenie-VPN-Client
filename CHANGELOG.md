# Changelog

Все значимые изменения Razreshenie VPN Client фиксируются в этом файле.

Формат основан на Keep a Changelog, версии следуют SemVer-подходу.

## 4.0.0 - 2026-06-17

Мажорный релиз 4.0.0 завершает большой цикл подготовки после 3.3.1: архитектура стала более модульной, сложные VPN-сценарии получили отдельные сервисы, тестовое покрытие расширено, UI advanced-групп отполирован, а стабильность подключения и диагностика усилены.

### Главное

- Подготовлена архитектурная база для дальнейшего развития 4.x.
- Smart Connect, Failover, Health Monitor, Advanced Groups и состояние приложения разделены по сервисам.
- Multi-hop и Load Balance стали полноценными целями подключения, а не только UI-настройками.
- Расширены unit- и integration-тесты для парсеров, config builder, routing/SRS, подписок, Smart Connect, Failover, updater и диагностики.
- Добавлен более строгий релизный процесс: self-check, release checklist, privacy/security gate и release diagnostics.

### Архитектура

- Основная логика подключения вынесена из GUI в сервисы: connection, runtime state, profile state, routing, subscription state и smart group workflows.
- Упрощена ответственность `gui/app.py`: GUI теперь меньше знает о деталях состояния профилей, подписок, маршрутизации и групп.
- Сборка sing-box config разделена по builder-слоям для outbound, inbound, DNS, route и advanced group outbounds.
- Runtime-учёт подключений вынесен в отдельную логику, чтобы аккуратно считать usage серверов и групп.
- Улучшена совместимость Smart Connect, Failover и Advanced Groups при ручном запуске, health recovery и reconnect.

### VPN-сценарии

- Добавлена стабильная поддержка advanced groups:
  - `Multi-hop` как цепочка outbound с `detour`;
  - `Load Balance` как sing-box `urltest` group outbound;
  - сохранение tag `proxy` для совместимости с текущей маршрутизацией.
- Улучшено ручное управление составом и порядком серверов в группах.
- Добавлена долгосрочная статистика usage для серверов и advanced-групп.
- Усилен встроенный российский bypass и работа со сложной маршрутизацией через JSON/TXT/SRS.

### UI/UX

- Улучшен редактор Smart/Fallback/Advanced Groups:
  - роли Entry/Middle/Exit для Multi-hop;
  - более понятные подсказки для Load Balance;
  - управление порядком серверов;
  - проверка минимального состава группы.
- Таблица групп получила больше контекста: режим, стратегия, участники, качество, usage и дата последнего подключения.
- Настройки сложных функций получили более точные названия и tooltips.
- Сложные сценарии стали лучше объяснены в документации и подсказках.

### Стабильность и ошибки

- Пользовательские ошибки стали понятнее:
  - отдельная категория Reality;
  - отдельная категория advanced groups;
  - отдельная категория updater;
  - более полезные TUN-сообщения.
- Reality-параметры `pbk/publicKey` и `sid/short_id` теперь проходят мягкую валидацию очевидно некорректных значений.
- Multi-hop и Load Balance больше не пропускают отсутствующих участников группы молча.
- Ошибки сборки advanced group теперь содержат контекст конкретного hop/member.
- Health recovery advanced-групп получил cooldown, чтобы не входить в быстрый цикл рестартов.
- Updater раньше отбрасывает пустые assets, пустые update scripts и некорректные checksum-сценарии.

### Диагностика

- Diagnostic ZIP расширен `state/stability-summary.redacted.json`.
- Диагностика включает агрегированные сведения о профилях, группах, routing/SRS, health/self-healing, runtime-состоянии и сессии логов.
- Redaction сохраняет приватность: URI, UUID, ключи, пароли, токены, адреса серверов, домены, IP и локальные пути скрываются.
- `--self-check` расширен проверками updater, diagnostics, routing/SRS, advanced groups и ошибок.

### Тестирование

- Расширен набор тестов до ключевых production-сценариев:
  - протокольные парсеры;
  - outbound/config builders;
  - Multi-hop и Load Balance config;
  - Smart Connect и Failover;
  - Health Monitor и self-healing;
  - подписки и importer;
  - updater;
  - diagnostics ZIP и redaction;
  - route builder и SRS.
- Добавлены integration-тесты для сложной маршрутизации и advanced group configs.
- Добавлен release gate для локальной проверки перед публикацией.

### Обновление приложения

- Поддерживается проверка GitHub Releases.
- Поддерживаются два режима:
  - скачать asset отдельно;
  - заменить текущий Windows EXE через временный локальный batch-файл.
- Для release assets рекомендуется публиковать `.exe` и `.exe.sha256`.

### Приватность и open source

- Проект остаётся GPLv3.
- Телеметрии нет.
- Диагностика создаётся локально и не отправляется автоматически.
- Пользовательские профили, подписки, правила, логи и статистика остаются локальными.
- Сохранена атрибуция zapret-kvn, Karing, russia-mobile-internet-whitelist и flag-icons.

### Совместимость и миграция

- Пользовательские JSON-данные остаются локальными и читаются через существующие модели.
- Старые Smart/Failover-группы продолжают открываться как `Failover`.
- Для advanced-групп рекомендуется открыть редактор группы и проверить порядок серверов перед первым запуском.
- Если Reality-профиль перестал собираться, проверьте `pbk/publicKey` и `sid/short_id`: 4.0.0 отбрасывает очевидно некорректные значения до запуска sing-box.
- Для in-place update используйте только проверенный `.exe` asset из GitHub Release.

### Известные ограничения

- Load Balance usage внутри группы распределяется между участниками равномерно, потому что текущий UI не получает точные per-outbound counters от sing-box.
- Health recovery advanced-группы перезапускает группу целиком, а не отдельный hop.
- TUN и Firewall Kill Switch требуют прав администратора и зависят от состояния Windows networking/firewall.
