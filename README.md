# Razreshenie VPN Client

**Razreshenie VPN Client** - открытый Windows VPN-клиент на Python, PyQt6 и sing-box.

**Версия:** `3.3.0`

Слоган: **«Разреши себе доступ к любым сайтам»**.

Проект распространяется как свободное ПО под лицензией **GPLv3**. Телеметрии нет, скрытого сбора данных нет. Профили, подписки, правила, логи и настройки хранятся локально в `%USERPROFILE%\Razreshenie VPN`.

Репозиторий проекта: <https://github.com/communism420/Razreshenie-VPN-Client>

## Документация

Подробные инструкции находятся в папке [docs](docs/README.md):

- [Первый запуск](docs/GETTING_STARTED.md) - установка, мастер первого запуска, импорт первого сервера и выбор Proxy/TUN.
- [Smart Connect](docs/SMART_CONNECT.md) - автоматический выбор лучшего сервера и история качества.
- [Failover](docs/FAILOVER.md) - группы серверов, health monitor и self-healing.
- [Multi-hop и Load Balance](docs/ADVANCED_GROUPS.md) - цепочки серверов, urltest-группы и ручные приоритеты.
- [Маршрутизация, bypass и SRS](docs/ROUTING_SRS.md) - split tunneling, rule-set ресурсы, geosite/geoip, process rules и приоритеты.
- [Поддерживаемые протоколы](docs/PROTOCOLS.md) - VLESS, Trojan, VMess, Hysteria2, TUIC, Shadowsocks и WireGuard.
- [Troubleshooting](docs/TROUBLESHOOTING.md) - типовые проблемы с подключением, DNS, TUN, bypass, плеерами и Firewall Kill Switch.
- [Сборка и релиз](docs/BUILD_RELEASE.md) - PyInstaller, version metadata и release checklist.
- [Приватность и безопасность](docs/PRIVACY_SECURITY.md) - локальные данные, сетевые запросы, диагностика ZIP и Kill Switch.

## Возможности

- GUI на PyQt6 + PyQt6-Fluent-Widgets с тёмной Fluent-темой.
- Proxy-режим через mixed SOCKS5/HTTP inbound.
- TUN-режим с auto route, IPv4/IPv6, DNS strategy и strict route.
- Импорт VLESS, Trojan, VMess, Hysteria2, TUIC v5, Shadowsocks 2022 и WireGuard.
- Импорт подписок: base64/plain-text, Clash YAML/JSON, sing-box JSON, v2rayN/Nekoray JSON и списки URI.
- Karing-style разбор названий серверов, групп, тегов и флагов.
- Smart Connect с выбором лучшего сервера по latency и истории качества.
- Failover-группы, health monitor и self-healing sing-box core.
- Multi-hop цепочки и Load Balance группы поверх sing-box outbounds.
- Ручное управление порядком серверов внутри группы.
- Долгосрочная статистика использования серверов и advanced-групп.
- Split tunneling через JSON/TXT/SRS, geosite, geoip и Windows process rules.
- Встроенный российский bypass с возможностью перекрывать его пользовательскими правилами.
- Live Activity: домены, маршруты, статистика и быстрое создание правил.
- Kill Switch для TUN и отдельный opt-in Firewall Kill Switch Windows.
- Диагностика ZIP с redaction секретов.
- Проверка обновлений приложения через GitHub Releases с режимом ручного скачивания или замены текущего EXE.
- Опциональный постоянный запуск от имени администратора с UAC при каждом обычном старте.
- Автосохранение настроек без отдельной кнопки сохранения.

## Быстрый запуск из исходников

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

Proxy-режим работает без прав администратора. TUN-режим запросит UAC при подключении, если у процесса нет прав администратора. В настройках можно включить постоянный UAC-запуск приложения.

## Проверка

```powershell
python -m compileall -q gui core models utils main.py tests
python -m unittest discover -s tests -v
python main.py --self-check
```

`--self-check` проверяет парсеры серверов, генерацию sing-box config, маршрутизацию, Smart Connect, диагностику, updater-логику и обработку ошибок без запуска GUI.

## Сборка EXE

Краткая команда:

```powershell
pyinstaller --noconfirm --clean --onefile --windowed `
  --name "Razreshenie VPN Client 3.3.0" `
  --icon assets\app.ico `
  --version-file tools\windows_version_info.txt `
  --collect-data qfluentwidgets `
  --hidden-import qfluentwidgets `
  --add-data "logo.webp;." `
  --add-data "assets;assets" `
  --distpath exe_release `
  main.py
```

Полный release checklist: [docs/BUILD_RELEASE.md](docs/BUILD_RELEASE.md).

## Атрибуция

Часть кода, графической архитектуры и дизайн-подходов Razreshenie VPN Client адаптированы из open-source проекта **zapret-kvn**:

<https://github.com/youtubediscord/zapret-kvn>

Отдельная благодарность open-source проекту **Karing** за подходы к названиям серверов, подпискам, проверке задержки через sing-box Clash API и устойчивому подключению:

<https://github.com/KaringX/karing>

Отдельная благодарность проекту **russia-mobile-internet-whitelist** за домены российского «белого списка»:

<https://github.com/hxehex/russia-mobile-internet-whitelist>

SVG-флаги стран взяты из проекта **flag-icons** под лицензией MIT:

<https://github.com/lipis/flag-icons>

## Open-source политика

Razreshenie VPN Client должен оставаться прозрачным и проверяемым:

- лицензия GPLv3;
- отсутствие телеметрии;
- сетевые запросы ограничены функциями клиента;
- пользовательские данные хранятся локально;
- диагностика ZIP создаётся локально и не отправляется автоматически;
- сборка воспроизводима из исходников.

Подробнее: [docs/PRIVACY_SECURITY.md](docs/PRIVACY_SECURITY.md).
