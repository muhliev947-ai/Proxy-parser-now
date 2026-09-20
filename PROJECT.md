# Proxy Subscription Builder — полная документация

**Версия:** 0.1.0
**Язык:** Python 3.11+
**Назначение:** автоматический сбор, проверка и публикация прокси-подписок для Hiddify

---

## 📖 Описание проекта

Проект представляет собой сервис, который:

1. **Собирает** публичные прокси-конфиги из интернета (GitHub-репозитории, подписки)
2. **Парсит** форматы VLESS, VMess, Trojan, Shadowsocks, Hysteria2
3. **Проверяет** их работоспособность через запущенный Hiddify (sing-box)
4. **Фильтрует** по типам, протоколам, скорости и доступности
5. **Генерирует** подписку в формате plain-text URI
6. **Публикует** её на GitHub Pages
7. **Обновляет** автоматически каждые 3 часа через GitHub Actions

---

## 🛠 Технологический стек

| Компонент | Технология |
|-----------|------------|
| Язык программирования | Python 3.11+ |
| Зависимости | PyYAML (единственная внешняя библиотека) |
| Тестирование | pytest |
| Линтинг и форматирование | ruff (dev-зависимость, extra `lint`) |
| Сборка | pyproject.toml (PEP 621) |
| CI/CD | GitHub Actions |
| Хостинг | GitHub Pages |
| Проверка прокси | Hiddify / sing-box 1.13.1 (Clash API) |
| Виртуальное окружение | venv |

**Ключевая особенность:** проект использует только стандартную библиотеку Python плюс PyYAML. Никаких тяжёлых фреймворков: сетевой ввод — `urllib`, проверка сокетов — `socket`, параллелизм — `ThreadPoolExecutor`.

---

## 📁 Структура проекта

```
Proxy-parser-now/
├── config.yaml                    # Конфигурация (источники, фильтры, проверка)
├── pyproject.toml                 # Метаданные пакета и зависимости
├── README.md                      # Краткая инструкция
├── PROJECT.md                     # ← Этот файл (подробная документация)
├── sample_proxies.txt             # Локальный fallback-файл с прокси
├── .gitignore                     # Исключения Git
│
├── src/                           # Исходный код
│   ├── __init__.py
│   ├── main.py                    # Точка входа, оркестрация pipeline
│   │
│   ├── parser/                    # Модуль парсинга
│   │   ├── __init__.py
│   │   ├── model.py               # Модель ProxyConfig (единый формат)
│   │   └── parser.py              # Парсинг URI, Base64, Clash YAML, Sing-box JSON
│   │
│   ├── checker/                   # Модуль проверки
│   │   ├── __init__.py
│   │   └── checker.py             # Проверка через Clash API Hiddify
│   │
│   └── generator/                 # Модуль генерации
│       ├── __init__.py
│       └── generators.py          # Генерация Clash YAML и Sing-box JSON
│
├── tests/                         # Тесты
│   ├── test_parser.py             # 23 теста: парсинг, REALITY round-trip
│   ├── test_checker.py            # 10 тестов: TCP/Clash API/SOCKS
│   ├── test_filters.py            # 7 тестов: фильтры конфига
│   └── test_generator.py          # 8 тестов: Clash/Sing-box/сортировка
│
├── output/                        # Результат сборки (локальный)
│   └── subscription.txt           # Сгенерированная подписка
│
├── docs/                          # Публикуется на GitHub Pages
│   ├── subscription.txt           # Копия подписки для Hiddify
│   ├── index.html                 # Стартовая страница
│   └── .nojekyll                  # Отключает Jekyll для GitHub Pages
│
└── .github/
    └── workflows/
        └── update.yml             # CI: сборка каждые 3 часа + деплой
```

---

## 🔄 Как это работает (pipeline)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        1. ИСТОЧНИКИ                                  │
│  config.yaml → список URL (jsDelivr зеркала GitHub-репозиториев)     │
└──────────────────────────────┬──────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        2. ПАРСИНГ                                    │
│  parse_sources() → parse_text() → parse_uri()                       │
│  Поддержка: plain-text URI, Base64-подписки, Clash YAML, Sing-box   │
│  Результат: list[ProxyConfig] — единый внутренний формат             │
└──────────────────────────────┬──────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     3. ФИЛЬТРАЦИЯ (парсер)                           │
│  - Удаление placeholder'ов (example.com, 127.0.0.1, demo)           │
│  - Удаление незашифрованных HTTP/SOCKS                               │
│  - Проверка UUID по формату                                          │
│  - Дедупликация по (type, server, port)                              │
└──────────────────────────────┬──────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        4. ПРОВЕРКА                                   │
│  check_proxy() через Clash API запущенного Hiddify                   │
│  - TCP connect до сервера                                           │
│  - REAL-хендшейк: GET /proxies/{tag}/delay через sing-box            │
│  - Только успешный проксированный запрос = узел рабочий              │
└──────────────────────────────┬──────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     5. ФИЛЬТРАЦИЯ (конфиг)                           │
│  - types: только указанные типы прокси                               │
│  - countries: только указанные страны                                │
│  - protocols: только указанные протоколы (reality, xhttp)            │
│  - min_speed_kbps: минимальная скорость                               │
│  - include_unchecked: публиковать ли непроверенные                    │
└──────────────────────────────┬──────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        6. ГЕНЕРАЦИЯ                                   │
│  to_plaintext_uris() → output/subscription.txt                      │
│  Копирование в docs/subscription.txt для GitHub Pages                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🧩 Модули и их назначение

### `src/parser/model.py` — модель данных

Единый внутренний формат `ProxyConfig`:

```python
@dataclass
class ProxyConfig:
    type: str                    # vless, vmess, trojan, ss, hy2
    server: str                  # адрес сервера
    port: int                    # порт
    name: str = ""               # имя узла
    uuid: str | None = None      # UUID для vless/vmess
    password: str | None = None  # пароль для trojan/hy2/ss
    method: str | None = None    # метод шифрования (ss)
    tls: bool = False            # включён ли TLS
    security: str | None = None  # tls | reality (ВАЖНО для хендшейка!)
    flow: str | None = None      # xtls-rprx-vision
    sni: str | None = None       # Server Name Indication
    fingerprint: str | None = None  # chrome, firefox
    encryption: str | None = None   # none
    mode: str | None = None      # gun (gRPC)
    network: str | None = None   # tcp, ws, grpc
    path: str | None = None      # путь для ws
    host: str | None = None      # Host заголовок
    service_name: str | None = None  # serviceName для gRPC
    reality: dict | None = None  # {public_key, short_id}
    # ... метрики проверки
    speed_kbps: float | None = None
    available: bool | None = None
    tcp_reachable: bool | None = None
    verified: bool = False       # прошёл REAL-проверку
```

**⚠️ Важный момент:** поле `security` критично. Если сервер использует REALITY, а в подписке написано `security=tls` — хендшейк падает. Это был главный баг проекта (подробнее в разделе «История багов»).

### `src/parser/parser.py` — парсинг

Функции:
- `parse_sources(sources, timeout, freshness_days, fallback_file)` — главный вход, читает все источники
- `parse_text(text)` — определяет формат (JSON/YAML/Base64/plain) и парсит
- `parse_uri(value)` — парсит одну URI-строку
- `to_plaintext_uris(proxies)` — генерирует финальные URI для подписки
- `_github_repo_files(repo, freshness_days)` — рекурсивно обходит GitHub-репозиторий через API

**Поддерживаемые форматы входных данных:**
- Plain-text: `vless://uuid@server:port?params#name`
- Base64: одна строка, декодируется в набор URI
- Clash YAML: `proxies: [{name, type, server, port, ...}]`
- Sing-box JSON: `{outbounds: [{type, tag, server, ...}]}`

**Защита от мусора:**
- `_is_placeholder_uri()` — отбрасывает example.com, localhost, demo, test
- `_is_real_proxy()` — проверяет UUID по regex, наличие password для trojan/ss
- `_should_skip_value()` — отбрасывает строки с publickey/placeholder
- Дедупликация по `(type, server, port)`

### `src/checker/checker.py` — проверка

```python
check_proxy(proxy, config) → ProxyConfig
```

**Двухэтапная проверка:**
1. **TCP connect** — быстрая проверка доступности порта
2. **Clash API** — реальный проксированный запрос через sing-box:
   ```
   GET /proxies/{tag}/delay?timeout=5000&url=https://cp.cloudflare.com/generate_204
   ```

**Проверка HTTP-статуса:** Clash API отдаёт `{"delay": N}` для любого доступного URL, включая 404/500 — он не различает статусы. Поэтому ответ дополнительно проверяется через SOCKS-инбаунд Hiddify (`socks5h://127.0.0.1:12334`), и узел считается рабочим только при совпадении с `expected_status` (по умолчанию 204).

**Почему именно так:** TCP connect не доказывает, что UUID, TLS, REALITY или WebSocket настройки валидны. Только реальный проксированный HTTP-запрос через sing-box даёт достоверный результат. А проверка только задержки пропустила бы узлы, отдающие 404/500.

**Разрешение тегов:** Clash API не отдаёт адреса серверов, только теги. Поэтому `load_hiddify_tags()` читает `~/.local/share/hiddify/data/current-config.json` и строит индекс `(server, port) → tag`.

**Динамическое обновление секрета:** Hiddify генерирует новый секрет при каждом перезапуске. Функция `load_hiddify_tags()` читает актуальный токен из `experimental.clash_api.secret` и обновляет глобальное состояние. Секрет из `config.yaml` используется только как fallback.

### `src/generator/generators.py` — генерация

- `to_clash(proxies)` — Clash YAML формат
- `to_singbox(proxies)` — Sing-box JSON формат
- `to_plaintext_uris(proxies)` — plain-text URI (основной формат для Hiddify)
- `sort_by_latency(proxies)` — сортировка по задержке, быстрые первыми

**Сортировка по задержке:** `speed_kbps` вычисляется как `8000 / delay`, поэтому большее значение = более быстрый узел. Непроверенные узлы (без измерения) помещаются в конец, сохраняя исходный порядок.

Включается параметром:
```yaml
output:
  sort_by_latency: true
```

### `src/main.py` — оркестрация

```python
build(config_path) → int  # количество рабочих прокси
```

Последовательность:
1. Чтение `config.yaml`
2. Парсинг источников
3. Ограничение кандидатов (`max_candidates`)
4. Очистка старых файлов подписки
5. Загрузка тегов Hiddify
6. Параллельная проверка (ThreadPoolExecutor)
7. Фильтрация
8. Генерация и запись

---

## ⚙️ Конфигурация (config.yaml)

### Источники

```yaml
sources:
  - https://cdn.jsdelivr.net/gh/Ruk1ng001/freeSub@main/v2ray
```

- URL или локальный путь
- Поддерживаются `http://`, `https://`, относительные пути
- `github:owner/repo` — рекурсивный обход через GitHub API
- **Сеть в РФ:** `raw.githubusercontent.com` недоступен, используется зеркало `cdn.jsdelivr.net/gh/`

### Фильтры

```yaml
freshness_days: 7          # только свежие файлы (для github: источников)
countries: []              # [] = все страны (RU, TR, NL, DE, PL)
types: [vless, vmess, trojan, ss, hy2]   # разрешённые типы
protocols: []              # [] = все (reality, xhttp, grpc, ws)
min_speed_kbps: 0          # минимальная скорость
```

### Проверка

```yaml
check:
  enabled: true
  require_protocol_handshake: true
  clash_api_url: http://127.0.0.1:16756
  clash_api_secret: MkueO0owlZajEXK7    # обновляется автоматически
  socks_proxy_url: socks5h://127.0.0.1:12334   # проверка HTTP-статуса
  expected_status: 204                  # только 204 = узел рабочий
  max_candidates: 500      # лимит для скорости
  timeout_seconds: 5       # TCP timeout
  concurrency: 8           # потоков
  urls: [https://cp.cloudflare.com/generate_204]
```

### Вывод

```yaml
output:
  directory: output
  formats: [plaintext]     # plaintext | clash | singbox
  sort_by_latency: true    # сортировка по задержке, быстрые первыми
  include_unchecked: false # false = только проверенные узлы
```

### Fallback

```yaml
fallback_file: sample_proxies.txt   # используется, если все источники недоступны
```

---

## 🚀 Установка и запуск

### Локальный запуск

```bash
# 1. Клонирование
git clone <repo-url>
cd Proxy-parser-now

# 2. Виртуальное окружение
python3 -m venv .venv
source .venv/bin/activate

# 3. Установка
pip install -e ".[test,lint]"

# 4. Тесты и линтер
python -m pytest -q
python -m ruff check src tests

# 5. Запуск
python -m src.main --config config.yaml --verbose
```

### Запуск без установки

```bash
python3 -m src.main --config config.yaml
```

### CLI-параметры

```bash
python -m src.main --help

опции:
  --config CONFIG   путь к конфигурации (по умолчанию: config.yaml)
  --verbose         подробный вывод (DEBUG-уровень)
```

### Результат

После выполнения файлы:
- `output/subscription.txt` — основная подписка
- `docs/subscription.txt` — копия для GitHub Pages

---

## 🧪 Тестирование

```bash
python -m pytest -q
```

**48 тестов** распределены по четырём файлам:

| Файл | Тестов | Что покрывает |
|------|--------|----------------|
| `tests/test_parser.py` | 23 | парсинг всех протоколов, Base64/YAML/JSON, отбрасывание мусора, round-trip REALITY |
| `tests/test_checker.py` | 10 | TCP-недоступность, Clash API-хендшейк, проверка HTTP-статуса через SOCKS, чтение секрета и тегов |
| `tests/test_filters.py` | 7 | фильтры по типу/стране/протоколу/скорости, `include_unchecked` |
| `tests/test_generator.py` | 8 | генерация Clash/Sing-box, сортировка по задержке |

Полный список того, что проверяется:

- Парсинг VLESS с REALITY
- Парсинг Base64-подписок
- Парсинг Clash YAML
- Генерацию Clash/Sing-box форматов
- Отбрасывание placeholder'ов
- Отбрасывание HTTP/SOCKS
- Fallback-механизм
- Round-trip сохранение REALITY-параметров (vless, vmess, trojan, **hy2**)
- Обратное направление: TLS не должен становиться REALITY
- Дедупликацию по `(type, server, port)`
- Валидацию UUID и обязательных паролей
- Отбрасывание loopback-адресов
- Парсинг Sing-box JSON
- TCP-недоступность → узел не проверяется
- TCP-доступность без Clash API → узел не подтверждён
- Успешный хендшейк через Clash API → узел подтверждён
- Ошибку Clash API → узел отклонён
- Несовпадение HTTP-статуса → узел отклонён
- Совпадение статуса → узел подтверждён
- Динамическое чтение секрета и тегов из `current-config.json`
- Синхронность `output/` и `docs/`
- Очистку устаревшей подписки при пустом результате
- Сортировку по задержке и её отключение по умолчанию

---

## 🔄 GitHub Actions

Файл: `.github/workflows/update.yml`

**Расписание:** `0 */3 * * *` — каждые 3 часа, плюс ручной запуск `workflow_dispatch`.

Пайплайн состоит из двух job'ов:

**Job `update`** — сборка и коммит:

1. Checkout репозитория
2. Установка Python 3.12
3. Установка проекта: `pip install -e ".[test,lint]"`
4. Валидация: `compileall` → `ruff check` → `pytest -q`
5. Сборка: `timeout 15m python -m src.main --config config.yaml --verbose`
6. Публикация в `docs/` (с защитой от утечки YAML-синтаксиса в подписку)
7. Авто-коммит через `git-auto-commit-action`

**Job `deploy`** — деплой статики (зависит от `update`):

1. `actions/upload-pages-artifact@v3` упаковывает папку `docs/`
2. `actions/deploy-pages@v4` публикует артефакт на GitHub Pages

> **Важно:** для job `deploy` требуется, чтобы в настройках репозитория **Settings → Pages → Source** было выбрано **GitHub Actions** (а не «Deploy from a branch»). Иначе будет конфликт с авто-коммитом в `docs/`.

**Ручной запуск:** вкладка Actions → "Update proxy subscriptions" → Run workflow

---

## 🌐 Публикация на GitHub Pages

1. Запушьте репозиторий на GitHub
2. Settings → Pages
3. Source: **GitHub Actions** (деплой идёт через `deploy` job из `update.yml`)
4. URL: `https://USERNAME.github.io/REPOSITORY/subscription.txt`

Файл `docs/.nojekyll` отключает обработку Jekyll, чтобы GitHub Pages отдавал файлы как есть.

Альтернатива — «Deploy from a branch» (ветка `master`, папка `/docs`), но тогда отключите job `deploy`, чтобы избежать гонки с авто-коммитом.

---

## 📱 Добавление в Hiddify

1. Откройте Hiddify
2. Профили → **Добавить подписку** (New Profile)
3. Вставьте URL:
   ```
   https://USERNAME.github.io/REPOSITORY/subscription.txt
   ```
4. Или вставьте содержимое файла вручную
5. Обновите подписку и выберите узел

**Формат:** plain-text, по одной URI на строку. Hiddify понимает этот формат напрямую.

---

## 🐛 История найденных багов

### 1. TCP-проверка вместо реального хендшейка

**Симптом:** в подписке 5924 узла, ни один не работает.

**Причина:** checker делал только `socket.create_connection()`. Открытый TCP-порт не доказывает, что UUID/TLS/REALITY валидны. Многие CDN-адреса принимают TCP, но не являются прокси.

**Решение:** проверка через Clash API запущенного Hiddify — реальный проксированный запрос.

### 2. REALITY превращался в TLS

**Симптом:** единственный рабочий узел не подключался в Hiddify.

**Причина:** генератор `to_plaintext_uris()` писал `security=tls` для всех узлов с TLS, даже если сервер использует REALITY. Сервер ждёт REALITY-handshake, клиент шлёт обычный TLS — соединение падает.

**Решение:** добавлено поле `security` в модель, генератор сохраняет оригинальное значение (`reality` или `tls`).

### 3. Потеря параметров gRPC

**Симптом:** REALITY-узел с gRPC-транспортом не работал.

**Причина:** генератор не сохранял `encryption`, `fp`, `mode`, `serviceName`.

**Решение:** все параметры теперь восстанавливаются. Добавлен регрессионный тест.

### 4. Устаревший секрет Clash API

**Симптом:** после перезапуска Hiddify все проверки падали с 401.

**Причина:** секрет хранился в `config.yaml` и не обновлялся. Hiddify генерирует новый при каждом старте.

**Решение:** `load_hiddify_tags()` читает актуальный секрет из `current-config.json`.

### 5. Scalar YAML ломал парсинг

**Симптом:** Base64-подписка с одной URI не парсилась.

**Причина:** `yaml.safe_load()` возвращал строку, код вызывал `.get()`.

**Решение:** проверка `isinstance(document, dict)`.

### 6. Незашифрованные HTTP/SOCKS принимались

**Симптом:** `parse_uri("http://user:pass@host:8080")` возвращал конфиг вместо `None`.

**Причина:** проверка схемы была `scheme not in SUPPORTED and not raw.count(":")`, и любой URI с двоеточием проходил.

**Решение:** явный `if scheme not in SUPPORTED: return None`.

### 7. Trojan-пароль терялся

**Симптом:** `trojan://PASSWORD@host:port` отбрасывался как узел без пароля.

**Причина:** `urlparse` кладёт credential trojan в `username`, а `.password` остаётся пустым.

**Решение:** для trojan/hy2 `password = user` если `password` пуст.

### 8. Ложное срабатывание на пароли

**Симптом:** любой пароль, содержащий подстроку `password` (например `secretpassword`), отбрасывался.

**Причина:** токен `"password"` в `_is_placeholder_uri()` матчил реальные пароли.

**Решение:** токен удалён, оставлены только реальные плейсхолдеры.

### 9. Стандартный vmess URI не парсился

**Симптом:** `vmess://UUID@host:port?params` возвращал `None`.

**Причина:** ветка vmess пыталась декодировать Base64 из всего, что идёт после `://`, даже для стандартного URI.

**Решение:** Base64-декодирование применяется только к legacy-формату.

### 10. Hysteria2 помечался как не-TLS

**Симптом:** `hy2://` узел не получал флаг `tls`, хотя Hysteria2 — это QUIC-over-TLS по определению протокола.

**Причина:** в `parse_uri()` флаг `tls` выставлялся только при `security=tls/reality` или для схемы `trojan`.

**Решение:** `hy2`/`hysteria2` теперь всегда подразумевают TLS. Покрыто тестом `test_hysteria2_uri_is_parsed`.

### 11. Фильтр по типу отбрасывал trojan

**Симптом:** фильтр `types: [trojan]` давал пустую подписку.

**Причина:** тестовый прокси-узел типа trojan создавался с `uuid`, но без `password`, а генератор `to_plaintext_uris()` справедливо не выпускает URI без обязательных учётных данных.

**Решение:** тестовый фикстур выдаёт UUID для vless/vmess и пароль для trojan/hy2/ss.

---

## 🔍 Качество кода

### Типизация

Все функции в `src/` имеют полные аннотации типов: `str | None`, `list[ProxyConfig]`, `dict[str, Any]`, `tuple[int, dict]`. Модель данных — `@dataclass` с `field(default_factory=dict)`. Используется синтаксис `X | Y` вместо `Optional[X]`.

### Линтинг

```bash
ruff check src tests
```

Конфигурация в `pyproject.toml`:

```toml
[tool.ruff]
line-length = 120
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "W", "I", "UP", "SIM", "RUF", "FURB", "LOG"]
ignore = ["E501"]
```

Линтер запускается и в CI — шаг *Validate parser* падает при любом нарушении.

### Definition of Done

Критерии приёмки, которым проект соответствует на данный момент:

1. **Линтеры и тесты** — `ruff check` и `pytest` возвращают 0 ошибок (48 тестов).
2. **Парсинг смешанных источников** — Base64, YAML и URI парсируются в одном потоке; битые строки (`garbage`, `://broken`, невалидный UUID/порт) отбрасываются, не роняя весь прогон.
3. **Валидация через Clash API** — мёртвые узлы отсекаются (`verified=False`), а параметры REALITY/gRPC (`security`, `pbk`, `sid`, `mode`, `serviceName`) сохраняются при round-trip.
4. **Читаемость подписки** — итоговый файл содержит только валидные URI, по одному на строку, без YAML-включений, и ре-парсится обратно.

---

## ⚠️ Ограничения

1. **Нужен запущенный Hiddify** — без него проверка невозможна, подписка будет пустой
2. **GitHub Actions не может проверять прокси** — там нет Hiddify, поэтому CI публикует пустую подписку. Это намеренно: лучше пусто, чем нерабочие узлы
3. **Свободные прокси живут недолго** — из 107 узлов за пару часов отвалились 2 из 3
4. **Сетевые ограничения в РФ** — `raw.githubusercontent.com` заблокирован, используется jsDelivr
5. **Telegram-источники** не поддерживаются (нужен Bot API токен)
6. **Битый YAML-элемент роняет весь файл** — если в `proxies:` встречается синтаксическая ошибка, `yaml.safe_load()` выбрасывает исключение и весь источник отбрасывается. Это сознательное решение: partial-YAML парсинг потребовал бы ручного строчного разбора, что не оправдано при наличии fallback-механизма

---

## 🔧 Отладка

### Проверить, запущен ли Hiddify

```bash
curl -sS http://127.0.0.1:16756/version
```

### Проверить конкретный узел

```bash
curl -sS -H "Authorization: Bearer SECRET" \
  "http://127.0.0.1:16756/proxies/TAG/delay?timeout=5000&url=https://cp.cloudflare.com/generate_204"
```

### Посмотреть актуальный секрет

```bash
python3 -c "
import json
d = json.load(open('~/.local/share/hiddify/data/current-config.json'.replace('~', __import__('os').path.expanduser('~'))))
print(d['experimental']['clash_api']['secret'])
"
```

### Подробные логи

```bash
python -m src.main --config config.yaml --verbose
```

---

## 📊 Статистика проекта

| Метрика | Значение |
|---------|----------|
| Тестов | 48 (23 parser + 10 checker + 7 filters + 8 generator) |
| Внешних зависимостей | 1 (PyYAML) |
| Dev-зависимостей | 2 (pytest, ruff) |
| Поддерживаемых протоколов | 5 (VLESS, VMess, Trojan, SS, HY2) |
| Входных форматов | 4 (plain, Base64, Clash YAML, Sing-box JSON) |
| Частота обновления | каждые 3 часа |
| Размер кодовой базы | ~811 строк Python (только `src/`) |
| Линтинг | ruff, 0 ошибок |

---

## 📝 Лицензия и этика

Проект работает **только с публичными источниками**. Никаких приватных репозиториев, личных аккаунтов или закрытых подписок. Вся информация берётся из открытых GitHub-репозиториев.

Использование бесплатных прокси несёт риски: трафик проходит через сторонние серверы. Не используйте для передачи конфиденциальных данных.
