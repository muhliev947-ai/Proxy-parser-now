# Proxy subscription builder

Модульный Python-сервис собирает открытые VLESS, VMess, Trojan, Shadowsocks и Hysteria2-конфигурации, приводит их к общей модели, фильтрует, выполняет опциональную сетевую проверку и генерирует подписки для Hiddify в Clash YAML и Sing-box JSON.

## Локальный запуск

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
python -m pytest
python -m src.main --config config.yaml --verbose
```

Результат находится в `output/subscription.yaml` и `output/subscription.json`. Для реального сетевого тестирования установите `check.enabled: true`; по умолчанию checks выключены, чтобы сборка была воспроизводимой и не требовала доступа к прокси.

## Конфигурация

`sources` содержит URL или пути к файлам. `countries` и `protocols` пустыми значениями отключают соответствующий фильтр. `types` задаёт разрешённые типы. `min_speed_kbps` задаёт нижний порог скорости. В секции `check` находятся timeout, URL контрольного запроса и число потоков. В `output` задаются каталог, форматы `clash`/`singbox` и правило включения непроверенных узлов.

## GitHub Pages и Actions

1. Создайте репозиторий и запушьте этот проект.
2. В **Settings → Pages** выберите `Deploy from a branch`, ветку `master`, папку `/docs`.
3. В **Actions** вручную запустите `Update proxy subscriptions` или дождитесь cron каждые 3 часа.
4. URL подписки будет `https://USERNAME.github.io/REPOSITORY/subscription.yaml` или `.json`.

Workflow копирует обновлённые файлы из `output` в `docs`, потому что GitHub Pages обслуживает только статические файлы из ветки `master`. Не добавляйте приватные источники или секреты в `config.yaml`: подписки и GitHub Pages публичны.

## Hiddify

Скопируйте URL опубликованного `subscription.yaml` или `subscription.json` в раздел добавления подписки Hiddify. При использовании Clash YAML выбирайте совместимый Clash-тип, при использовании JSON — Sing-box.

## Ограничения

Проверка доступности выполняет TCP connect и короткий HTTP-запрос через локальную сеть; она не является полноценным VPN handshake или измерением пропускной способности через каждый протокол. Telegram-источники требуют отдельного Bot/API токена и намеренно не включены по умолчанию.