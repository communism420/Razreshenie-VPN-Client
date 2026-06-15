# Документация Razreshenie VPN Client

Эта папка содержит пользовательские и релизные инструкции для версии 3.0.0. README в корне проекта оставлен как краткая карта, а подробные сценарии вынесены сюда.

## Быстрые ссылки

- [Первый запуск](GETTING_STARTED.md) - установка, мастер первого запуска, импорт первого сервера и выбор режима.
- [Smart Connect](SMART_CONNECT.md) - автоматический выбор лучшего сервера и история качества.
- [Failover](FAILOVER.md) - группы серверов, health monitor и self-healing.
- [Multi-hop и Load Balance](ADVANCED_GROUPS.md) - цепочки серверов, urltest-группы и ручные приоритеты.
- [Маршрутизация, bypass и SRS](ROUTING_SRS.md) - split tunneling, rule-set ресурсы, geosite/geoip и приоритеты.
- [Поддерживаемые протоколы](PROTOCOLS.md) - URI, JSON-импорт и особенности outbound для sing-box.
- [Troubleshooting](TROUBLESHOOTING.md) - типовые проблемы и безопасная диагностика.
- [Сборка и релиз](BUILD_RELEASE.md) - PyInstaller, version-info и release checklist.
- [Приватность и безопасность](PRIVACY_SECURITY.md) - хранение данных, сетевые запросы, диагностика ZIP и Kill Switch.

## Для кого какие документы

- Новому пользователю достаточно пройти [Первый запуск](GETTING_STARTED.md), затем открыть [Troubleshooting](TROUBLESHOOTING.md), если что-то не работает.
- Пользователю с большой подпиской полезны [Smart Connect](SMART_CONNECT.md), [Failover](FAILOVER.md) и [Multi-hop/Load Balance](ADVANCED_GROUPS.md).
- Для сложного split tunneling нужен [гайд по маршрутизации](ROUTING_SRS.md).
- Перед сборкой EXE или публикацией GitHub Release используйте [Сборка и релиз](BUILD_RELEASE.md).
