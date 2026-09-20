# Proxy subscription builder

Модульный Python-сервис собирает зашифрованные VLESS, VMess, Trojan, Shadowsocks и Hysteria2-конфигурации, приводит их к общей модели, фильтрует, выполняет опциональную сетевую проверку и генерирует для Hiddify plain-text список URI, по одной ссылке на строку.

## Локальный запуск

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
python -m pytest
python -m src.main --config config.yaml --verbose
```

Результат находится в `output/subscription.txt` и синхронизируется в `docs/subscription.txt`. В выдачу попадают только `vless://`, `vmess://`, `ss://`, `trojan://` и `hy2://` с обязательными credentials; публичные HTTP/SOCKS-прокси и демонстрационные узлы отбрасываются. TCP connect сам по себе не подтверждает UUID/password, TLS, Reality или WebSocket, поэтому без установленного sing-box/xray backend строгий режим не публикует узлы как рабочие.

## Конфигурация

`sources` содержит URL или пути к файлам, включая plain-text и Base64 подписки. `countries` и `protocols` пустыми значениями отключают соответствующий фильтр. `types` задаёт разрешённые типы. В секции `check` находятся timeout, URL контрольного запроса, число потоков и `max_candidates`, ограничивающий размер сетевого прогона. Формат `plaintext` является основным.

## GitHub Pages и Actions

1. Создайте репозиторий и запушьте этот проект.
2. В **Settings → Pages** выберите `Deploy from a branch`, ветку `master`, папку `/docs`.
3. В **Actions** вручную запустите `Update proxy subscriptions` или дождитесь cron каждые 3 часа.
4. URL подписки будет `https://USERNAME.github.io/REPOSITORY/subscription.txt`.

Workflow копирует обновлённые файлы из `output` в `docs`, потому что GitHub Pages обслуживает только статические файлы из ветки `master`. Не добавляйте приватные источники или секреты в `config.yaml`: подписки и GitHub Pages публичны.

## Hiddify

Скопируйте URL опубликованного `subscription.txt` в раздел добавления подписки Hiddify. Файл содержит только готовые URI, по одной ссылке на строку, без YAML-синтаксиса.

## Ограничения

Проверка доступности выполняется через Clash API запущенного Hiddify (sing-box 1.13.1): узел считается рабочим только если реальный проксированный HTTP-запрос к `cp.cloudflare.com/generate_204` завершился успешно. Обычный TCP connect не считается доказательством, поскольку он не проверяет UUID, TLS, Reality или WebSocket.

Для работы проверки необходим запущенный Hiddify с включённым Clash API. Параметры `check.clash_api_url` и `check.clash_api_secret` в `config.yaml` должны указывать на активное ядро. Если Hiddify не запущен, подписка не будет содержать узлов, вместо публикации непроверенных серверов.

Свободные прокси быстро устаревают: из 107 зашифрованных узлов проверку в текущем запуске прошли только единицы. Telegram-источники требуют отдельного Bot/API токена и намеренно не включены по умолчанию.