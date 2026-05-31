# Razreshenie VPN Client

**Razreshenie VPN Client** — открытый VPN-клиент на Python для Windows.

**Версия:** `1.0.0`

Слоган: **«Разреши себе доступ к любым сайтам»**.

Проект распространяется как свободное ПО под лицензией **GPLv3**. Код открыт, телеметрии нет, скрытых функций нет, сбор пользовательских данных не выполняется. Профили, подписки, правила и настройки хранятся локально.

Репозиторий проекта: <https://github.com/communism420/Razreshenie-VPN-Client>

## Атрибуция

Часть кода, графической архитектуры и дизайн-подходов Razreshenie VPN Client адаптированы из open-source проекта **zapret-kvn**:

<https://github.com/youtubediscord/zapret-kvn>

Спасибо авторам zapret-kvn за открытую работу. Razreshenie VPN Client является отдельным проектом и сохраняет собственную лицензию GPLv3.

## Возможности

- GUI на PyQt6 + PyQt6-Fluent-Widgets с темной Fluent-темой в стиле zapret-kvn.
- VLESS import из `vless://` ключей.
- Импорт подписок в base64 или plain-text.
- sing-box core с автоматической загрузкой последнего Windows x64 release.
- Proxy-режим через mixed inbound SOCKS5/HTTP.
- TUN-режим с virtual adapter, auto route, strict route для kill switch.
- Split tunneling через локальный JSON или raw GitHub URL.
- Live-окно активности доменов: видно, какие текущие домены и поддомены идут через VPN, а какие напрямую, с фильтром по словам.
- Логи, экспорт логов, DNS-проверка, системный трей.
- Автообновление подписок и автозапуск Windows.
- Все пользовательские данные, настройки, профили, правила, логи и sing-box core хранятся в `%USERPROFILE%\Razreshenie VPN`.

## Быстрый запуск из исходников

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

Для TUN-режима запустите приложение от имени администратора. Proxy-режим работает без прав администратора.

## Проверка кода

```powershell
python -m compileall -q .
python main.py --self-check
```

`--self-check` проверяет парсер VLESS и генерацию базового sing-box config без запуска GUI.

## Маршрутизация JSON

Поддерживаются структуры с ключами:

- `domains`, `domain`, `domain_suffix`, `domain_keyword`
- `ip`, `ips`, `ip_cidr`, `cidr`
- `process_name`, `process_path_regex`

Пример:

```json
{
  "domains": ["example.com", "*.example.org"],
  "ip_cidr": ["1.1.1.1/32", "8.8.8.0/24"]
}
```

Можно загрузить несколько локальных JSON-файлов или прямых raw-ссылок GitHub, например:

```text
https://raw.githubusercontent.com/communism420/My-Karing-Ruleset/refs/heads/main/griffini.json
```

Для каждого JSON-набора в интерфейсе отдельно задается маршрут:

- `Текущий сервер` — совпавший трафик идет через активный VLESS-профиль.
- `Напрямую` — совпавший трафик идет в обход VPN.

После добавления JSON настройте его маршрут прямо в строке таблицы в колонке `Туннелирование`.

## Активность доменов

Вкладка `Активность` показывает свежие домены и поддомены, которые `sing-box` упоминает в runtime-логах. Для каждой записи отображается маршрут: `VPN` или `Напрямую`, правило JSON, количество запросов и время последнего появления.

Фильтр принимает одно или несколько слов: например `google video` покажет только домены, где встречаются оба слова.

## Сборка в один EXE через PyInstaller

1. Установите зависимости:

```powershell
python -m pip install -r requirements.txt
```

2. Создайте `.ico`:

```powershell
python tools\create_icon.py
```

3. Соберите один EXE без консоли, с иконкой и запросом прав администратора для TUN:

```powershell
pyinstaller --noconfirm --clean --onefile --windowed `
  --name "Razreshenie VPN Client" `
  --icon assets\app.ico `
  --uac-admin `
  --collect-data qfluentwidgets `
  --hidden-import qfluentwidgets `
  --add-data "logo.webp;." `
  --add-data "assets;assets" `
  main.py
```

EXE появится в папке `dist`.

Если нужен build только для Proxy-режима без постоянного запроса UAC, уберите `--uac-admin`. В этом случае TUN-режим потребует ручного запуска EXE от имени администратора.

## Open-source политика

Razreshenie VPN Client должен оставаться прозрачным и проверяемым:

- лицензия GPLv3;
- отсутствие телеметрии;
- отсутствие скрытых сетевых запросов, кроме запросов, инициированных пользователем: загрузка sing-box, подписок, правил, проверки IP/DNS;
- хранение пользовательских данных локально;
- воспроизводимая сборка из исходников.
