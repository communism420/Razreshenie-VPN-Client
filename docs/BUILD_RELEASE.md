# Сборка и релиз 4.0.0

Этот checklist описывает локальную подготовку Windows-релиза Razreshenie VPN Client. Он не требует `git push`, `git commit` или действий с удалённым репозиторием.

## 0. Цель release gate

Перед публикацией нужно подтвердить:

- версия в коде, документации и Windows metadata синхронизирована;
- тесты и `--self-check` проходят локально;
- diagnostic ZIP не раскрывает секреты;
- updater корректно видит release assets и checksum;
- EXE запускается в Proxy и TUN сценариях;
- open-source атрибуции и privacy/security документы актуальны.

## 1. Подготовка окружения

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Проверьте, что используется ожидаемый Python:

```powershell
python --version
python -c "import PyQt6, qfluentwidgets, requests, yaml, psutil; print('deps ok')"
```

## 2. Синхронизация версии

Для релиза `4.0.0` должны совпадать:

- `utils/version.py` -> `APP_VERSION`;
- `tools/windows_version_info.txt` -> `filevers`, `prodvers`, `FileVersion`, `ProductVersion`;
- `README.md`;
- `NOTICE.md`;
- `licenses/OPEN_SOURCE_POLICY.md`;
- `CHANGELOG.md`;
- имя EXE или `--name` в PyInstaller;
- tag GitHub Release, если публикация выполняется вручную.

Локальная проверка:

```powershell
python tools\release_check.py
```

## 3. Проверка кода перед сборкой

```powershell
python -m compileall -q core gui main.py tests models utils tools
python -m unittest discover -s tests -v
python main.py --self-check
python tools\release_check.py
git diff --check
```

`git diff --check` может показать предупреждения Git о будущей CRLF-нормализации. Это не ошибка whitespace, если exit code равен `0`.

## 4. Проверка документации

Перед сборкой проверьте:

- `CHANGELOG.md` содержит раздел `4.0.0`;
- `docs/README.md` ссылается на актуальные гайды;
- `docs/PRIVACY_SECURITY.md` описывает in-place updater и diagnostic ZIP;
- `docs/TROUBLESHOOTING.md` содержит Reality, TUN, updater и diagnostic ZIP сценарии;
- `docs/ADVANCED_GROUPS.md` описывает Multi-hop, Load Balance, missing members и recovery cooldown;
- `docs/PROTOCOLS.md` описывает Reality `pbk/publicKey` и `sid/short_id`;
- `README.md` содержит ссылку на changelog и полный checklist.

## 5. Privacy/security gate

Проверьте перед релизом:

- в коде нет телеметрии, аналитики и скрытых сетевых отправок;
- diagnostic ZIP создаётся локально и не отправляется автоматически;
- redaction скрывает URI, UUID, пароли, токены, ключи, домены, IP и локальные пути;
- updater скачивает только выбранный GitHub Release asset;
- in-place updater использует локальный временный batch-файл и не запускается для исходников;
- Firewall Kill Switch явно описан как opt-in и fail-closed риск;
- `NOTICE.md` и `licenses/OPEN_SOURCE_POLICY.md` сохраняют атрибуции zapret-kvn, Karing, russia-mobile-internet-whitelist и flag-icons.

## 6. Генерация иконки

```powershell
python tools\create_icon.py
```

После этого должен существовать файл:

```text
assets/app.ico
```

## 7. Сборка через основной spec

Рекомендуемый путь:

```powershell
pyinstaller --noconfirm --clean --distpath exe_release "Razreshenie VPN Client.spec"
```

Ожидаемый artifact:

```text
exe_release\Razreshenie VPN Client 4.0.0.exe
```

## 8. Альтернативная сборка одной командой

Если spec не используется:

```powershell
pyinstaller --noconfirm --clean --onefile --windowed `
  --name "Razreshenie VPN Client 4.0.0" `
  --icon assets\app.ico `
  --version-file tools\windows_version_info.txt `
  --collect-data qfluentwidgets `
  --hidden-import qfluentwidgets `
  --exclude-module PyQt5 `
  --exclude-module PySide6 `
  --exclude-module PySide2 `
  --exclude-module torch `
  --exclude-module matplotlib `
  --exclude-module scipy `
  --exclude-module pytest `
  --exclude-module IPython `
  --exclude-module django `
  --exclude-module tkinter `
  --add-data "logo.webp;." `
  --add-data "assets;assets" `
  --distpath exe_release `
  main.py
```

## 9. SHA256 для release asset

```powershell
$exe = "exe_release\Razreshenie VPN Client 4.0.0.exe"
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
"$hash  Razreshenie VPN Client 4.0.0.exe" | Set-Content -Encoding ascii "$exe.sha256"
```

Release assets:

```text
Razreshenie VPN Client 4.0.0.exe
Razreshenie VPN Client 4.0.0.exe.sha256
```

Checksum asset рекомендуется публиковать рядом с EXE. Updater 4.0.0 откажется от checksum asset, если он есть, но не содержит SHA256 для файла обновления.

## 10. Smoke test собранного EXE

Запустите EXE из `exe_release` и проверьте:

1. Открывается главное окно.
2. В `О проекте` отображается версия `4.0.0`.
3. Proxy-режим стартует без администратора.
4. TUN-режим запрашивает UAC и стартует с администраторскими правами.
5. Импорт одиночной ссылки работает.
6. Импорт подписки работает и ошибки показываются понятным текстом.
7. Smart Connect выбирает кандидата и пишет результат в логи.
8. Failover-группа стартует обычный профиль.
9. Multi-hop-группа собирается и запускается как цепочка.
10. Load Balance-группа собирается как `urltest`.
11. Health Monitor не уходит в быстрый цикл рестартов advanced-группы.
12. Live Activity показывает домены и создаёт правила.
13. JSON/TXT/SRS routing import работает.
14. Diagnostic ZIP создаётся и содержит `state/stability-summary.redacted.json`.
15. Update check видит GitHub Release и корректно показывает режим установки.

## 11. Проверка updater вручную

Для опубликованного release:

1. Убедитесь, что tag совпадает с `v4.0.0` или `4.0.0`.
2. Убедитесь, что Windows asset имеет расширение `.exe`, `.msi` или `.zip`.
3. Для in-place update используйте `.exe`.
4. Проверьте, что checksum asset содержит строку вида:

```text
<sha256>  Razreshenie VPN Client 4.0.0.exe
```

5. В настройках проверьте оба режима:
   - `Скачать отдельно`;
   - `Заменить текущий EXE`.

## 12. Финальная публикационная проверка

Перед публикацией release notes должны включать:

- ссылку на `CHANGELOG.md`;
- список главных изменений 4.0.0;
- предупреждение, что TUN/Firewall Kill Switch требуют администратора;
- заметку, что diagnostic ZIP редактирует секреты, но пользователь должен проверить архив перед публичной отправкой;
- список release assets и checksum.

## 13. Откат

Если smoke test EXE не проходит:

1. Не публикуйте release asset.
2. Сохраните failing logs и diagnostic ZIP локально.
3. Исправьте проблему в исходниках.
4. Повторите весь checklist с пункта 3.

Если проблема найдена после публикации:

1. Пометьте release как pre-release или удалите проблемный asset.
2. Подготовьте patch release `4.0.1`.
3. В `CHANGELOG.md` явно опишите исправление.
