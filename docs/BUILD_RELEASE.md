# Сборка и релиз

Документ описывает локальную сборку Windows EXE через PyInstaller.

## Проверка перед сборкой

```powershell
python -m compileall -q gui core models utils main.py tests
python -m unittest discover -s tests -v
python main.py --self-check
```

## Синхронизация версии

Перед релизом проверьте:

- `utils/version.py`;
- `tools/windows_version_info.txt`;
- имя `.spec` или параметр `--name`;
- имя EXE в `exe_release`;
- tag GitHub Release, если релиз публикуется.

## Сборка

```powershell
python -m pip install -r requirements.txt
python tools\create_icon.py
pyinstaller --noconfirm --clean --onefile --windowed `
  --name "Razreshenie VPN Client 3.2.1" `
  --icon assets\app.ico `
  --version-file tools\windows_version_info.txt `
  --collect-data qfluentwidgets `
  --hidden-import qfluentwidgets `
  --add-data "logo.webp;." `
  --add-data "assets;assets" `
  --distpath exe_release `
  main.py
```

Готовый файл появится в `exe_release`.

## Release assets

Для updater желательно приложить:

```text
Razreshenie VPN Client 3.2.1.exe
Razreshenie VPN Client 3.2.1.exe.sha256
```

Checksum asset опционален, но если он есть, клиент сверит SHA256 скачанного файла.

## После сборки

1. Запустите EXE без прав администратора и проверьте Proxy.
2. Проверьте TUN через UAC.
3. Проверьте импорт одиночной ссылки и подписки.
4. Проверьте Smart Connect toggle.
5. Проверьте экспорт диагностики ZIP.
6. Проверьте, что metadata EXE показывает правильную версию.
