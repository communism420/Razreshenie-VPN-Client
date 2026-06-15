# Маршрутизация, bypass и SRS

Razreshenie VPN Client строит секцию `route` sing-box из пользовательских наборов правил, внешних rule-set ресурсов и встроенного bypass.

## Основные понятия

`Текущий сервер` означает маршрут через активный VPN outbound.

`Напрямую` означает маршрут через sing-box `direct` outbound.

Правила применяются сверху вниз. Пользовательские наборы имеют приоритет выше встроенного российского bypass.

## Поддерживаемые наборы

JSON может содержать:

```json
{
  "domains": ["example.com", "*.example.org"],
  "domain_keyword": ["video"],
  "domain_regex": ["(^|\\.)example\\.net$"],
  "geosite": ["category-ru"],
  "geoip": ["private"],
  "ip_cidr": ["1.1.1.1/32"],
  "process_name": ["telegram.exe"],
  "process_path_regex": ["(?i).*\\\\chrome\\.exe$"],
  "rule_set": ["ru-sites"]
}
```

TXT поддерживает по одному правилу на строку:

```text
wildberries.ru
*.example.com
geosite:ru
geoip:private
1.1.1.0/24
telegram.exe
process_path:C:\Program Files\App\app.exe
process_path_regex:(?i).*\\chrome\.exe$
```

## SRS rule-set

Файлы `.srs` не разворачиваются в домены. Клиент создаёт ресурс `route.rule_set` и правило, которое ссылается на его `tag`.

Поддерживаются:

- локальные `.srs` файлы;
- удалённые raw URL на `.srs`;
- binary format sing-box.

Удалённые SRS получают `update_interval`, чтобы sing-box мог обновлять rule-set самостоятельно.

## Приоритеты

Во вкладке `Маршрутизация` используйте кнопки `Выше` и `Ниже`. Чем выше набор, тем раньше он попадает в runtime config.

Рекомендация:

1. Точные исключения для проблемных сайтов.
2. Правила приложений через `process_name` или `process_path_regex`.
3. SRS/geosite/geoip наборы.
4. Общий bypass.

## Live Activity

Вкладка `Активность` показывает домены из runtime-логов sing-box. Из выбранной строки можно создать правило:

- точный домен;
- зона домена;
- маршрут `Напрямую`;
- маршрут `Через VPN`.

Такие правила сохраняются в агрегированные наборы Live Activity и сразу учитываются при следующей сборке config.

## Windows process rules

Для Windows лучше начинать с `process_name`, например `telegram.exe`. Если приложение запускается из разных путей, используйте `process_path_regex`.

Регулярные выражения должны учитывать обратные слэши Windows:

```text
process_path_regex:(?i).*\\Telegram Desktop\\Telegram\.exe$
```

## Частые ошибки

- Два SRS ресурса с одинаковым `tag` невалидны.
- Правило ссылается на `rule_set`, которого нет в `route.rule_set`.
- Слишком общий bypass может отправить CDN плеера напрямую, хотя сам сайт идёт через VPN.
- Некоторые приложения игнорируют системный proxy, поэтому для них нужен TUN.
