# Guest Agent Protocol 1.0

## Статус

Реализованы binary-safe framing, потоковое чтение/запись, дедупликация ответов, JSON-команды, Linux x86-64 agent, Rust host client и `QemuAgent` с нативными QMP checkpoints. Unix-socket, stdio и virtio-console transport проверены интеграционными тестами, включая полный guest-сценарий под pinned QEMU и CoW-snapshot. Реализация и автоматическая приёмка VF-03 готовы к ревью. Преобразование raw mappings в Contracts v2 `MappingRecord` относится к VF-06; `advance_clock` и replay префиксов — к VF-08. Эта проверка не закрывает production-детерминизм VF-02 и не заменяет VM-фикстуры VF-04.

## Назначение и границы

Один кадр содержит один request или response. Payload — произвольная последовательность байт, включая NUL и non-UTF-8; framing не использует строки с завершающим нулём, разделители или текстовый escaping.

SHA-256 обнаруживает повреждение payload, но не аутентифицирует отправителя. Канал agent должен быть отдельным от stdin/stdout цели и недоступным исследуемому процессу. Протокол сам по себе не разрешает guest path и не выполняет действия.

## Кадр

Все многобайтовые целые числа кодируются little-endian. Заголовок всегда занимает 96 байт, за ним следует ровно `payload_length` байт. Других данных в кадре нет.

| Смещение | Размер | Поле |
| ---: | ---: | --- |
| 0 | 4 | magic, ASCII `VFAG` |
| 4 | 1 | major version, `1` |
| 5 | 1 | minor version, `0` |
| 6 | 1 | kind: `1=request`, `2=response` |
| 7 | 1 | flags, все биты зарезервированы и равны нулю |
| 8 | 2 | header length, `96` |
| 10 | 2 | reserved, нули |
| 12 | 8 | request ID, ненулевой `u64` |
| 20 | 8 | action index, беззнаковый индекс в `TestCase.actions` |
| 28 | 16 | EpisodeId: 16 ASCII-цифр без префикса `episode-` |
| 44 | 16 | StepId: 16 ASCII-цифр без префикса `step-` |
| 60 | 4 | payload length, `u32` |
| 64 | 32 | SHA-256 именно payload, без заголовка |
| 96 | payload length | payload |

Версия 1.0 проверяется строго: другой major или minor отклоняется. Неизвестные kind/flags, ненулевые reserved, другой header length, неканонические IDs и нулевой request ID также отклоняются. При разборе action index проверяется представимость в host `usize`; сложение длин выполняется с overflow check.

`Codec::decode` принимает ровно один кадр и отклоняет trailing bytes. `Codec::read` читает один кадр из `Read`, оставляя следующий кадр в потоке, и корректно собирает фрагментированные reads. EOF до завершения заголовка или payload — `Truncated`.

## Идентичность и дедупликация

Response повторяет EpisodeId, StepId, action index и request ID своего request; `Frame::response_for` сохраняет эту связь.

Ключ дедупликации: `(EpisodeId, StepId, request ID)`. `ResponseCache::respond_with` работает так:

1. Для нового ключа один раз вызывает операцию, проверяет идентичность response и сохраняет пару request/response.
2. Для байт-в-байт одинакового повторного request возвращает сохранённый response, не вызывая операцию.
3. Если тот же ключ использован с другим action index или payload, возвращает `ConflictingRequest` и не вызывает операцию.

Кэш находится в памяти и не является журналом восстановления после перезапуска agent. При разрыве соединения результат запроса может быть неизвестен: host client не повторяет автоматически деструктивное действие. Безопасный путь — восстановить чистый snapshot и повторить весь префикс сценария с новой идентичностью запуска; восстановление ambiguous in-flight запроса требует отдельного протокола и здесь не заявляется.

## Лимиты и ошибки

Максимальный payload реализации — 16 MiB на кадр. `Codec::new` может установить меньший лимит, включая нулевой для пустых payload. Заявленная длина проверяется до выделения payload buffer. Несоответствие SHA-256, truncation, trailing bytes, overflow и превышение лимита — явные `ProtocolError`, а не частично принятое сообщение.

Лимит кадра не заменяет отдельные лимиты размера файла, stdin, stdout/stderr, числа argv, длины пути и времени исполнения. Они должны быть заданы в сообщениях действий и runner.

## JSON payload

Envelope остаётся бинарным; payload кадра содержит один строгий JSON-объект с `deny_unknown_fields`. Все произвольные байты (`argv_hex`, `cwd_hex`, `path_hex`, `data_hex`, `value_hex`) кодируются строчным hex без потери NUL и non-UTF-8. `WireAction::from(&Action)` преобразует Contracts v2 действие, а wire-вариант дополнительно допускает non-UTF-8 guest path, непредставимый в JSON `String`.

Операция `execute` содержит один `WireAction`: `write_file`, `set_env`, `spawn_process` или `write_stdin`. Непосредственный guest agent возвращает `unsupported_action` для `advance_clock` и `checkpoint`: он не имитирует snapshot или виртуальные часы. `QemuAgent` выполняет `checkpoint` через QMP; `advance_clock` остаётся явно unsupported до VF-08.

Host-only операции `observe_process`, `wait_process`, `terminate_process` и `shutdown` управляют уже созданным `process_ref` и не добавляют новых действий в Contracts v2 `Action[]`. `wait_process` имеет миллисекундный лимит и флаг `kill_on_timeout`; timeout отличается от exit/signal. После SIGKILL процесс ожидается через `wait`, чтобы не оставлять zombie.

Response имеет `status=success|error`. Ошибка содержит машинный `code` и пояснение; contract violation, spawn error, agent I/O, unknown process и unsupported action различаются. Host client проверяет kind и Episode/Step/action/request identity до разбора результата. Transport failure делает клиент непригодным для следующих вызовов: автоматического retry, в том числе повторного spawn/write, нет.

## Выполнение и наблюдения

- `spawn_process` вызывает `Command` непосредственно, без shell; argv[0] является executable. Окружение сначала очищается, затем применяются только предшествующие `set_env`. Имена env не содержат NUL/`=`, значения могут быть non-UTF-8, но не NUL. При root-запуске agent цель получает UID/GID 65534 и пустой supplementary groups list; без root сохраняются текущие effective credentials и группы. Это не позволяет цели открыть root-only control device и не наследовать его descriptor.
- `write_file` и `cwd` принимают только абсолютные пути внутри canonical `--workspace`. Parent components, выход через symlink и не-Regular file отклоняются; финальный файл открывается с Linux `O_NOFOLLOW`, mode применяется к открытому descriptor. Agent не создаёт host path по guest path и не пишет вне workspace.
- Agent возвращает PID, TGID и Linux start time как `start_generation`, SHA-256 executable и сырые записи `/proc/<pid>/maps`. Это ещё не подтверждённые `MappingRecord`: BinaryId, load bias, address space и mapping generation должен проверить coverage backend.
- stdout/stderr дренируются отдельными потоками. Сохраняется ограниченный префикс, SHA-256 всех прочитанных байт, полное число байт, `truncated` и `complete`. Незавершённый или оборванный capture нельзя считать полным отрицательным наблюдением.
- Наблюдаются stdout/stderr, результат процесса и подтверждённая agent-запись файла. Системные file/network/clock effects пока не трассируются и не должны выдаваться за отсутствующие.

По умолчанию лимиты составляют 4 MiB на file/stdin, 64 KiB сохранённого вывода на поток, 128 argv, 1 MiB на argument, 256 env entries и 32 process refs. Запись stdin имеет отдельный 5-секундный таймаут; при нём цель уничтожается. Общий лимит кадра остаётся 16 MiB.

## QEMU и checkpoints

`QemuAgent` соединяет обычный `AgentClient` с отдельным QMP Unix-сокетом. QMP messages ограничены 1 MiB, имеют проверяемый request ID; asynchronous events пропускаются и не принимаются за response. Ошибка QMP, failed job и timeout различаются.

Для checkpoint вызывается нативный QMP `snapshot-save`, а не формируемая строка HMP. Конфигурация обязана явно задать `vmstate_device` и полный `writable_devices`; vmstate node обязан входить в список. После `snapshot-save` клиент ждёт `query-jobs → concluded`, проверяет отсутствие job error и выполняет `job-dismiss`. `job-finalize` не используется: snapshot job финализируется автоматически. Дубликат tag не считается успехом независимо от того, возвращён он синхронной QMP-ошибкой или failed job.

VM-приёмочный тест использует `scripts/build-agent-initramfs.sh`: read-only initramfs, tmpfs workspace, BusyBox и отдельный `virtconsole`. Скрипт настраивает TTY в `raw -echo`, пока удерживает descriptor открытым, затем удаляет лишний descriptor до запуска agent. Это необходимо для binary framing: canonical mode/echo повреждают кадры, а настройка через временно открытый descriptor может сбрасываться. QEMU получает CoW-overlay над qcow2 base; SHA-256 initramfs и base сравниваются до и после сценария.

## Запуск

```sh
cargo build --locked --bin vuln-fuzz-agent
vuln-fuzz-agent --workspace /tmp/vf-work --socket /run/vuln-fuzz/agent.sock
# Либо для подключённого QEMU character device:
vuln-fuzz-agent --workspace /tmp/vf-work --stdio
```

Unix transport принимает одно соединение и создаёт socket с mode `0600`. Stdio предназначен для отдельного QEMU character device, а не для stdin/stdout исследуемой цели. Оба варианта сами по себе не создают VM-изоляцию: backend обязан предоставить отдельный канал, read-only исходный образ и CoW workspace.

## Проверка

```sh
cargo test --locked --test agent
cargo test --locked --test agent_runtime -- --test-threads=1
cargo test --locked --test agent_qemu

# Реальная VM-приёмка; kernel должен быть доступен на чтение:
VF_TEST_KERNEL=/path/to/vmlinuz \
VF_TEST_QEMU="$PWD/build/qemu/qemu-system-x86_64" \
VF_TEST_QEMU_IMG="$PWD/build/qemu/qemu-img" \
cargo test --locked --test agent_qemu -- --ignored --nocapture
```

Тесты покрывают framing, версии и reserved fields, truncation, lengths/trailing bytes, oversized payload, hash mismatch, IDs и дедупликацию. End-to-end тесты запускают настоящий agent и проверяют Unix/stdio transport, NUL/non-UTF-8 argv/path/stdin/env, большой вывод и digest, PID/mappings, timeout/SIGKILL/reaping, malformed JSON, foreign response identity, зависший agent без retry, path traversal и symlink escape. QMP mock проверяет events, job completion/dismiss и ошибки конфигурации. Отдельный ignored тест загружает Linux в pinned QEMU, выполняет binary file/spawn/stdin/wait сценарий, проверяет mappings, UID 65534, запрет доступа цели к `/dev/hvc0`, CoW-checkpoint, duplicate tag и неизменность исходных образов.
