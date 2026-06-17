# Поддерживаемые протоколы

Один профиль работает и в Proxy, и в TUN режиме. Разница только во входящем inbound sing-box; outbound собирается одинаково.

| Протокол | Импорт | Основные поля |
| --- | --- | --- |
| VLESS | `vless://`, sing-box/Clash/Nekoray JSON | UUID, TLS, Reality, flow, transport, mux |
| Trojan | `trojan://`, JSON | password, TLS, Reality |
| VMess | `vmess://`, JSON | UUID, security, alterId, TCP/WS/gRPC/HTTP transport |
| Hysteria2 | `hysteria2://`, `hy2://`, JSON | password, QUIC, obfs salamander, bandwidth |
| TUIC v5 | `tuic://`, JSON | UUID, password, congestion control |
| Shadowsocks | `ss://`, JSON | method, password, Shadowsocks 2022 methods |
| WireGuard | `wireguard://`, sing-box JSON | private key, peer public key, local addresses |

## VLESS

VLESS требует UUID. Reality параметры берутся из URI или JSON: `sni`, `pbk`, `sid`, `fp`, `spx`. Для XTLS flow используется параметр `flow`.

В 4.0.0 клиент заранее отбрасывает очевидно некорректные Reality значения:

- `pbk/publicKey` должен выглядеть как base64url public key без пробелов;
- `sid/short_id` должен быть hex-строкой чётной длины до 16 символов.

Если профиль не собирается, сначала проверьте именно эти поля в ссылке или JSON.

## Trojan

Trojan требует `password`. TLS включается по умолчанию, Reality поддерживается через sing-box TLS config и проходит ту же предварительную проверку `pbk/publicKey` и `sid/short_id`.

## VMess

VMess требует UUID. Reality для VMess не поддерживается и отклоняется при сборке outbound. Security по умолчанию `auto`, если профиль не задаёт другой cipher.

## Hysteria2

Hysteria2 требует password. Если включён obfs, должен быть указан `obfs-password`. Bandwidth параметры нормализуются в `up_mbps` и `down_mbps`, когда они есть в профиле.

## TUIC v5

TUIC требует UUID и password. Дополнительно поддерживаются congestion control, UDP relay mode и TLS параметры.

## Shadowsocks 2022

Shadowsocks требует method и password. Методы 2022 передаются в sing-box как обычный Shadowsocks outbound.

## WireGuard

WireGuard считается опциональным протоколом. Для корректной работы нужны private key, peer public key, endpoint, local addresses и при необходимости reserved bytes.

## Где смотреть ошибку

Если профиль не собирается в sing-box config, откройте:

- вкладку `Логи`;
- кнопку проверки JSON профиля;
- `python main.py --self-check` для проверки базовых сценариев.
