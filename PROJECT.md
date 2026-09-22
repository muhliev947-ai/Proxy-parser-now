# Proxy Subscription Builder — полная документация

**Версия:** 0.1.0
**Язык:** Python 3.11+
**Назначение:** автоматический сбор, проверка и публикация прокси-подписок для Hiddify

---

## 📖 Описание проекта

Проект представляет собой сервис, который:

1. **Собирает** публичные прокси-конфиги из интернета (GitHub-репозитории, подписки)
2. **Парсит** форматы VLESS, VMess, Trojan, Shadowsocks, Hysteria2
3. **Проверяет** их работоспособность — два режима:
   - **Hiddify-режим** (локальный): через запущенный Hiddify с Clash API
   - **CI-режим (Varianta B)**: `LocalSingBoxBackend` — один sing-box на всех кандидатов, каждый кандидат получает свой `mixed` inbound, проверка идёт параллельно
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
│   ├── main.py                    # Точка входа (Hiddify-режим), тонкая обёртка над pipeline.build
│   │
│   ├── parser/                    # Модуль парсинга
│   │   ├── __init__.py
│   │   ├── model.py               # Модель ProxyConfig (единый формат)
│   │   └── parser.py              # Парсинг URI, Base64, Clash YAML, Sing-box JSON
│   │
│   ├── checker/                   # Модуль проверки
│   │   ├── __init__.py
│   │   ├── checker.py             # Проверка через Clash API Hiddify (Hiddify-режим)
│   │   ├── pipeline.py            # Общий pipeline: build(), HiddifyBackend, LocalSingBoxBackend
│   │   └── launch_singbox.py     # CI-режим: standalone запуск sing-box без Hiddify
│   │
│   └── generator/                 # Модуль генерации
│       ├── __init__.py
│       └── generators.py          # Clash YAML, Sing-box JSON, to_singbox_parallel (Varianta B)
│
├── tests/                         # Тесты (70+4 интеграционных)
│   ├── test_parser.py             # 26 тестов: парсинг, REALITY round-trip, partial-YAML
│   ├── test_checker.py            # 10 тестов: TCP/Clash API/SOCKS
│   ├── test_filters.py            # 7 тестов: фильтры конфига
│   ├── test_generator.py          # 8 тестов: Clash/Sing-box/сортировка
│   ├── test_publication.py        # 4 теста: пул узлов, финальная перепроверка
│   ├── test_launch_singbox.py     # 15 тестов: Varianta B, batch halving, secrets, ports
│   └── test_integration_singbox.py # 5 тестов: реальный sing-box (skipif при отсутствии бинаря)
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

**Пул рабочих узлов:** проверка не останавливается на первом найденном узле. Пока не набрано `min_working_nodes` (по умолчанию 5) живых узлов, проверяются следующие батчи кандидатов — бесплатные прокси умирают за часы, поэтому один узел это хрупкая подписка. `max_total_candidates` ограничивает общую работу, чтобы мёртвая сеть не затянула прогон.

**Финальная перепроверка:** прямо перед записью подписки топовые узлы перепроверяются (`reverify_top_n`, по умолчанию 10). Узел, живой минуту назад, может уже быть мёртвым, и перепроверка гарантирует, что в подписку не попадёт протухший узел.

**Проверка HTTP-статуса:** Clash API отдаёт `{"delay": N}` для любого доступного URL, включая 404/500 — он не различает статусы. Поэтому ответ дополнительно проверяется через SOCKS-инбаунд Hiddify (`socks5h://127.0.0.1:12334`), и узел считается рабочим только при совпадении с `expected_status` (по умолчанию 204).

**Почему именно так:** TCP connect не доказывает, что UUID, TLS, REALITY или WebSocket настройки валидны. Только реальный проксированный HTTP-запрос через sing-box даёт достоверный результат. А проверка только задержки пропустила бы узлы, отдающие 404/500.

**Разрешение тегов:** Clash API не отдаёт адреса серверов, только теги. Поэтому `load_hiddify_tags()` читает `~/.local/share/hiddify/data/current-config.json` и строит индекс `(server, port) → tag`.

### `src/checker/pipeline.py` — общий pipeline

Общий код для обоих режимов. Основные сущности:

```python
build(config_path, backend) → int  # количество рабочих прокси
_check_with_pool(candidates, backend, check) → list[ProxyConfig]
_reverify_before_publish(proxies, backend, check) → list[ProxyConfig]
_write_freshness_metadata(final, backend) → None
redact(message: str) → str  # удалеие секретов из лог-сообщений
_RedactFilter(logging.Filter)  # автоматический фильтр для логгера
```

**Pool-growth loop** (`_check_with_pool`):
1. `batch_size = max(concurrency * 4, min_working_nodes)`
2. Цикл: берём `batch_size` кандидатов, запускаем sing-box (или Hiddify), проверяем батч
3. После каждого батча считаем `verified` — если `verified >= min_working_nodes`, останавливаемся
4. Если кандидатов нет — останавливаемся
5. `max_total_candidates` (по умолчанию `max_candidates * 4`) жёстко ограничивает общее число проверенных кандидатов, чтобы мёртвая сеть не затянула прогон

**Empty-pub guard:** если проверенных узлов ноль и существующего файла `subscription.txt` нет — ничего не записывается, log-сообщение «No verified proxies and no existing subscription found; nothing written». Если файл существует — он сохраняется как есть.

**Redaction** (`redact()`):
- Удаляет из лог-сообщений: `uuid=…`, `password=…`/`pwd=…`, `pbk=…`, `sid=…`, `Bearer <token>`, голые UUID-токены, полные proxy-URI (остаётся только схема).
- Применяется в `LocalSingBoxBackend._spawn_with_halving` (stderr-хвост), `verify_batch` (exception-сообщение), `_log_candidate_result` (reason), и в предупреждении о drop при reverify.
- `_RedactFilter` подключается к модульному логгеру `LOG` pipeline'а и к корневому логгеру в `main()` и `launch_singbox.py`.

**Динамическое обновление секрета:** Hiddify генерирует новый секрет при каждом перезапуске. Функция `load_hiddify_tags()` читает актуальный токен из `experimental.clash_api.secret` и обновляет глобальное состояние. Секрет из `config.yaml` используется только как fallback.

### `src/generator/generators.py` — генерация

- `to_clash(proxies)` — Clash YAML формат
- `to_singbox(proxies)` — Sing-box JSON формат (Hiddify-режим)
- `to_singbox_parallel(proxies, base_port, clash_api_port, clash_api_secret)` — Varianta B: один mixed inbound на кандидата, route.rules привязка
- `filter_supported_outbounds(proxies)` — разделение на (supported, unsupported)
- `to_plaintext_uris(proxies)` — plain-text URI (основной формат для Hiddify)
- `sort_by_latency(proxies)` — сортировка по задержке, быстрые первыми

**Сортировка по задержке:** `speed_kbps` вычисляется как `8000 / delay`, поэтому большее значение = более быстрый узел. Непроверенные узлы (без измерения) помещаются в конец, сохраняя исходный порядок.

Включается параметром:
```yaml
output:
  sort_by_latency: true
```

### `src/main.py` — оркестрация (Hiddify-режим)

```python
build(config_path) → int  # количество рабочих прокси
```

Тонкая обёртка над `pipeline.build()` с HiddifyBackend. Последовательность:
1. Чтение `config.yaml`
2. Парсинг источников
3. Ограничение кандидатов (`max_candidates`)
4. Загрузка тегов Hiddify
5. Параллельная проверка (ThreadPoolExecutor)
6. Фильтрация, сортировка, reverify
7. Генерация и запись

**CI-режим (Varianta B):** `python -m src.checker.launch_singbox` — использует `LocalSingBoxBackend`, Hiddify не требуется.

### `src/checker/pipeline.py` — общий pipeline

Общий код для обоих режимов. Основные сущности:

```python
build(config_path, backend) → int
_check_with_pool(candidates, backend, check) → list[ProxyConfig]
_reverify_before_publish(proxies, backend, check) → list[ProxyConfig]
_write_freshness_metadata(final, backend) → None
redact(message: str) → str
_RedactFilter(logging.Filter)
```

**Pool-growth loop** (`_check_with_pool`):
- `batch_size = max(concurrency * 4, min_working_nodes)`
- Цикл: берём `batch_size` кандидатов, запускаем sing-box (или Hiddify), проверяем батч
- После каждого батча считаем `verified` — если `verified >= min_working_nodes`, останавливаемся
- Если кандидатов нет или достигнут `max_total_candidates` — останавливаемся
- `max_total_candidates` (по умолчанию `max_candidates * 4`) жёстко ограничивает общее число проверенных кандидатов

**Empty-pub guard:**
- Если проверенных узлов ноль и `output/subscription.txt` не существует — ничего не записывается (log: «No verified proxies and no existing subscription found; nothing written»)
- Если файл существует — он сохраняется как есть, новый прогон не чистит подписку

**Redaction** (`redact()`):
- Удаляет из лог-сообщений: `uuid=…`, `password=…`/`pwd=…`, `pbk=…`, `sid=…`, `Bearer <token>`, голые UUID-токены, полные proxy-URI (остаётся только схема)
- Применяется: `LocalSingBoxBackend._spawn_with_halving` (stderr-хвост), `verify_batch` (exception-сообщение), `_log_candidate_result` (reason), предупреждение о drop при reverify
- `_RedactFilter` подключается к модульному логгеру `LOG` pipeline'а и к корневому логгеру в `main()` и `launch_singbox.py`

**Freshness metadata** (`_write_freshness_metadata`):
- При успешной сборке (есть проверенные узлы, plaintext-формат) записывает в `docs/index.html` под маркером `<!-- freshness-meta -->`: время последнего успешного чека (UTC), количество узлов, разбивку по типам
- `docs/subscription.txt` и `output/subscription.txt` остаются чистым списком URI без метаданных
- Время берётся из `backend.last_log_time` (для `LocalSingBoxBackend`) или из `time.gmtime()`

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

**87 тестов** (skipif при отсутствии sing-box) распределены по десяти файлам:

| Файл | Тестов | Что покрывает |
|------|--------|----------------|
| `tests/test_parser.py` | 26 | парсинг всех протоколов, Base64/YAML/JSON, отбрасывание мусора, round-trip REALITY, partial-YAML recovery |
| `tests/test_checker.py` | 10 | TCP-недоступность, Clash API-хендшейк, проверка HTTP-статуса через SOCKS, чтение секрета и тегов |
| `tests/test_filters.py` | 7 | фильтры по типу/стране/протоколу/скорости, `include_unchecked` |
| `tests/test_generator.py` | 8 | генерация Clash/Sing-box, сортировка по задержке |
| `tests/test_publication.py` | 4 | пул рабочих узлов, финальная перепроверка, фильтры до проверки |
| `tests/test_launch_singbox.py` | 15 | Varianta B: один inbound на кандидата, batch halving, secrets, free ports, pool-growth, empty-pub guard |
| `tests/test_redaction.py` | 7 | `redact()`: UUID, password, pbk/sid, bearer, mask whole URI, safe metadata passes, filter cleans slipped args |
| `tests/test_integration_singbox.py` | 5 | реальный sing-box: `check -c`, фильтрация xhttp, REALITY outbound (валидный x25519 ключ) проходит check, dead-node rejection, полный lifecycle (skipif) |

**Интеграционные тесты** прогоняются при наличии бинарика:
```bash
SINGBOX_BIN=./sing-box python -m pytest tests/test_integration_singbox.py -v
```

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
5. Загрузка sing-box 1.13.1 (pin + SHA-256 verification: `e68f9a19...`)
6. Включение `check.singbox.enabled: true` в config.yaml (Python-сниппет)
7. Сборка: `timeout 15m python -m src.checker.launch_singbox --config config.yaml --singbox ./sing-box`
   - При таймауте (rc=124) — публикует частичные результаты (empty-pub guard)
   - `--verbose` логирует без URIs и секретов
8. Публикация в `docs/`: если `output/subscription.txt` не пуст — копирует; иначе сохраняет существующую подписку
9. Авто-коммит через `git-auto-commit-action`

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

### 12. Битый YAML-элемент ронял весь источник

**Симптом:** крупный агрегатор `mfuu/v2ray` (1000+ узлов) отдавал 0 узлов, а подписка оставалась с одним-единственным узлом.

**Причина:** в файле встречалась строка с вложенными кавычками, `name: "FR-"2001:bc8:...:"-0055"`. `yaml.safe_load()` выбрасывал `ParserError`, и весь источник отбрасывался целиком.

**Решение:** добавлен partial-YAML recovery — `_parse_yaml_proxies()` при ошибке переходит к блочному сканированию (`_parse_yaml_blocks()`), которое восстанавливает каждый валидный элемент вокруг битого, а `_repair_yaml_quotes()` санирует вложенные кавычки и мусор в скалярах (`port: 443?`). Теперь `mfuu/v2ray` отдаёт 1014 узлов. Покрыто тремя регрессионными тестами.

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

1. **Линтеры и тесты** — `ruff check` и `pytest` возвращают 0 ошибок (87 тестов, включая redaction, pool-growth, empty-pub guard, и 5 интеграционных с реальным sing-box).
2. **Парсинг смешанных источников** — Base64, YAML и URI парсируются в одном потоке; битые строки (`garbage`, `://broken`, невалидный UUID/порт) отбрасываются, не роняя весь прогон.
3. **Валидация через Clash API** — мёртвые узлы отсекаются (`verified=False`), а параметры REALITY/gRPC (`security`, `pbk`, `sid`, `mode`, `serviceName`) сохраняются при round-trip.
4. **Читаемость подписки** — итоговый файл содержит только валидные URI, по одному на строку, без YAML-включений, и ре-парсится обратно.
5. **CI-режим (Varianta B)** — `LocalSingBoxBackend` запускает sing-box без Hiddify; batch halving изолирует битые outbounds; empty-pub guard сохраняет существующую подписку при нуле проверенных узлов.
6. **Безопасность** — в `--verbose` логах нет URI-линков и Clash API секретов; `clash_api_secret` генерируется через `secrets.token_hex(16)` на каждый запуск.

---

## ⚠️ Ограничения

1. **Нужен запущенный Hiddify** — в Hiddify-режиме без него проверка невозможна. CI-режим (Varianta B) не требует Hiddify: sing-box запускается standalone.
2. **CI-проверка ≠ проверка из РФ** — GitHub Actions работает на датацентре в США/Европе. Узел, доступный из датацентра, может быть недоступен из России (обратное тоже). Hiddify-режим на локальной машине точнее. Это не баг, а ограничение среды.
3. **Свободные прокси живут недолго** — из 107 узлов за пару часов отвалились 2 из 3
4. **Сетевые ограничения в РФ** — `raw.githubusercontent.com` заблокирован, используется jsDelivr
5. **Telegram-источники** не поддерживаются (нужен Bot API токен)
6. **Свежесть узлов** — бесплатные прокси быстро устаревают; даже из 2000 распарсенных кандидатов REAL-проверку через Hiddify проходят единицы. Это не баг парсера, а природа публичных подписок: `include_unchecked: false` гарантирует, что в подписку попадают только реально рабочие узлы. Если живых узлов меньше, чем `min_working_nodes`, подписка содержит столько, сколько нашлось — лучше один проверенный узел, чем ноль или сотня непроверенных.
7. **Batch halving — не параметр конфига** — размер батча и глубина деления (max 8) жёстко заданы в коде; нельзя настроить из `config.yaml`.
8. **xhttp / httpupgrade** — эти транспорты не поддерживаются sing-box и отфильтровываются автоматически; кандидаты с ними не включаются в проверку.
9. **uTLS / reality в CI** — синтаксис конфиг-секции `tls.utls` требует поля `enabled: true` и валидный `public_key` (base64/x25519). Условный фильтр reality был удалён; если часть узлов всё ещё отклоняется (некорректный ключ, отсутствующий SNI), лог `Dropping unsupported outbound … security=reality` показывает причину. `utls.enabled` и `utls.fingerprint` (`chrome` по умолчанию) проставляются автоматически генератором.

### Reference: `check.singbox` config section

```yaml
check:
  singbox:
    enabled: false            # false в локальном Hiddify-режиме; CI workflow включает
    binary: ./sing-box       # путь к бинарнику sing-box (CI скачивает в ./sing-box)
    wait_seconds: 30          # макс. секунд ожидания готовности Clash API порта
    max_outbounds: 500        # лимит outbound'ов в одном экземпляре sing-box
    concurrency: 8            # параллельные HTTP-запросы через dedicated inbounds
    port_per_candidate: 1    # один mixed inbound на кандидата (Variant B)
```

**Filter-ы перед генерацией конфига:** `xhttp`/`httpupgrade` (несовместимые транспорты). Эти узлы не попадают в sing-box, но остаются в подписке — фильтр только локальной проверки, не генерации.

**REALITY-поддержка:** фиксированный sing-box 1.13.1 собирается с тегом `with_utls`, поэтому фильтр по типу `reality` отсутствует. Причина ошибок «uTLS is required by reality client» была не в отсутствующем uTLS, а в некорректных x25519 публичных ключах (padded base64 или не та длина). При валидном 43-символьном unpadded x25519 ключе `sing-box check -c` возвращает rc=0. Генератор `to_singbox_parallel` автоматически добавляет `tls.utls.enabled=true` и `tls.utls.fingerprint` (по умолчанию `chrome`) для всех REALITY-узлов.

---

## 🔍 Как читать ошибки узлов

Узел может не работать по-разному, и диагностика помогает понять, что именно не так:

| Симптом | Что значит |
|---------|------------|
| `ConnectionRefusedError` на TCP | Порт закрыт — сервер мёртв или сменил адрес |
| TCP OPEN, но `TimeoutError: timed out` в `/delay` | Порт принимает соединения, но REALITY/TLS-хендшейк или проксирование не состоялось — узел для нас бесполезен |
| `An error occurred in the delay test` | sing-box не смог установить соединение вообще (чаще всего сервер мёртв) |
| `{"delay": N}`, но HTTP-статус ≠ 204 | Узел работает, но отдаёт не то (перенаправление/блокировка) |
| `401 Unauthorized` от Clash API | Устаревший секрет Hiddify — перезапустите `load_hiddify_tags()` |

**Получить точную ошибку для узла:**

```bash
# Узнать тег узла в конфиге Hiddify
python3 -c "
from src.checker.checker import load_hiddify_tags
print(load_hiddify_tags().get(('176.109.104.195', 9873)))
"

# Запросить реальный хендшейк
TAG='...'
SECRET=$(python3 -c "import json,pathlib; print(json.load(pathlib.Path.home().joinpath('.local/share/hiddify/data/current-config.json').open())['experimental']['clash_api']['secret'])")
curl -sS -H "Authorization: Bearer $SECRET" \
  "http://127.0.0.1:16756/proxies/$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$TAG")/delay?timeout=8000&url=https://cp.cloudflare.com/generate_204"
```

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
| Тестов | 87 (26 parser + 10 checker + 7 filters + 8 generator + 4 publication + 15 launch_singbox + 7 redaction + 5 integration + 5 pool-growth) |
| Внешних зависимостей | 1 (PyYAML) |
| Dev-зависимостей | 2 (pytest, ruff) |
| Поддерживаемых протоколов | 5 (VLESS, VMess, Trojan, SS, HY2) |
| Входных форматов | 4 (plain, Base64, Clash YAML, Sing-box JSON) |
| Частота обновления | каждые 3 часа |
| Размер кодовой базы | ~1200 строк Python (только `src/`) |
| Линтинг | ruff, 0 ошибок |

---

## 📝 Лицензия и этика

Проект работает **только с публичными источниками**. Никаких приватных репозиториев, личных аккаунтов или закрытых подписок. Вся информация берётся из открытых GitHub-репозиториев.

Использование бесплатных прокси несёт риски: трафик проходит через сторонние серверы. Не используйте для передачи конфиденциальных данных.

---
