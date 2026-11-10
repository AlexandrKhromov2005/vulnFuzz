# Контракты vulnFuzz v2

Статус: **draft VF-01**, 10.11.2026. Версия v2 заменяет draft v1 до начала реализации: единицей анализа становится сценарий цепочки VM-состояний, а не один входной файл. Физический 512-байтовый mmap ABI v1 не утверждён и не должен использоваться как готовая спецификация.

Нормативная область: исследовательский MVP из [ROADMAP.md](../ROADMAP.md), Linux x86-64 guest, qemu-system и qemu-user, guest agent, детерминированные snapshots, concolic DSE процесса с Z3. Слова **MUST**, **MUST NOT**, **SHOULD** обозначают обязательное требование, запрет и рекомендацию.

## 1. JSON и совместимость

- Каждый самостоятельный JSON-артефакт содержит `schema_version: "vulnFuzz/v2"` и `artifact`.
- Неизвестные версия, artifact и поля v2 отклоняются как `SchemaError`; молчаливое игнорирование опечаток запрещено.
- JSON — UTF-8. Произвольные байты входов, argv и env кодируются полями `*_hex` строчными hex-строками чётной длины. Строковые пути guest — UTF-8; неподдерживаемые байтовые пути явно отклоняются до добавления отдельного представления.
- Адреса, offsets, load bias, ELF sizes и виртуальные timestamps — `HexU64`: `0x` + ровно 16 строчных hex-цифр. Так сохраняется `0xffffffffffffffff`.
- Счётчики, PID, коды идентификаторов, длительности wall time и лимиты — JSON integer в явно заданном диапазоне. Виртуальные наносекунды используют HexU64, wall milliseconds — integer.
- SHA-256 — `sha256:` + 64 строчных hex-символа. Хеш содержимого нельзя заменять путём, build-id или версией пакета.
- `null` допускается только для явно необязательного значения. Отсутствие наблюдения, `unknown`, `unsupported` и ошибка — разные состояния, а не пустые строки.
- Сохранённые пути артефактов кампании — относительные, без `..` и абсолютного host path. Guest paths в TestCase не используются как host paths.

### 1.1. Канонизация

Для content-addressed объектов соответствующее поле ID исключается, остальное сериализуется по RFC 8785 (JCS) в UTF-8 и хешируется SHA-256.

- `ScenarioId` вычисляется от TestCase без `scenario_id`; порядок `actions` семантический и не сортируется.
- `AnalysisRevision` вычисляется от AnalysisModel без `analysis_revision`; blocks/edges/unknowns сортируются по правилам раздела 5.
- `SnapshotId` вычисляется от snapshot descriptor, содержащего SHA-256 RAM/device state/CoW layers и VM config; само содержимое хранится отдельно.
- `TestCase` и модель не содержат wall-clock timestamps, абсолютные host paths или случайные RunId внутри хешируемой части.

Изменение схемы, идентичности адресов, SourceId, действий или качества покрытия требует новой версии и миграции либо явного отказа чтения старые кампании.

## 2. Идентификаторы

| Тип | Представление и инвариант |
| --- | --- |
| `VmImageId` | SHA-256 immutable image descriptor и всех базовых слоёв; путь не является ID |
| `SnapshotId` | `sha256:...` snapshot descriptor; restore обязан проверить хеш |
| `BinaryId` | SHA-256 точных байтов исследуемого ELF |
| `ScenarioId` | `sha256:...` канонического TestCase |
| `EpisodeId` | `episode-` + 16 десятичных цифр; одно исполнение сценария внутри кампании |
| `StepId` | `step-` + 16 десятичных цифр; результат одного действия внутри Episode |
| `StateId` | SnapshotId узла state graph; логический узел дополнительно имеет lineage |
| `BlockId` | `{ binary_id, start_elf_va }`; стабилен при росте AnalysisModel |
| `MappingId` | `map-` + 16 десятичных цифр; поколение конкретного runtime mapping внутри кампании |
| `AnalysisRevision` | `sha256:...` канонической AnalysisModel |
| `DseTargetId` / `DseAttemptId` | Стабильные campaign-scoped `dse-target-N`, `dse-attempt-N` |
| `FindingId` | `finding-` + стабильный номер кампании |

EpisodeId назначается даже при ошибке запуска VM. StepId назначается действию, которое началось; не начавшееся действие остаётся `not_started` в журнале сценария, а не получает фиктивный результат.

## 3. Адреса и mappings

| Тип | Значение |
| --- | --- |
| `FileOffset` | Offset от начала ELF |
| `ElfVa` | Статическая VA из ELF, единая координата BlockId |
| `GuestVa` | VA в конкретном guest address space |
| `LoadBias` | Смещение конкретного mapping; вычисляется и проверяется заново |

Все диапазоны полуоткрытые `[start,end)`, арифметика проверяется. Для файловой части `PT_LOAD`:

```text
delta = elf_va - p_vaddr                  # elf_va >= p_vaddr
file_offset = p_offset + delta            # delta < p_filesz
guest_va = elf_va + load_bias
elf_va = guest_va - load_bias
```

BSS и дырки между сегментами не имеют файловых байтов. Принадлежность PC проверяется по конкретному executable range, а не по интервалу min/max.

`MappingRecord` содержит:

- `mapping_id`, `binary_id`, `load_bias`;
- backend address-space identity (для x86-64 system — CR3 и generation; ASID добавляется при наличии);
- PID/TGID и guest process start generation; PID без generation не является уникальным;
- `guest_start`, `guest_end`, executable ranges;
- `first_seen_step`, `last_seen_step | null`, `source` и verification evidence.

Новый exec, изменение bias/CR3, unload/remap или неоднозначное соответствие создаёт новый MappingId либо `MappingError`. Первый PC, интерпретатор и host `/proc/<qemu-pid>/maps` не используются как доказательство mapping главного ELF.

`CodeObservation = (EpisodeId, StepId, MappingId, BlockId)`. Одного BlockId недостаточно для воспроизведения runtime-наблюдения.

## 4. TestCase и действия

`TestCase` содержит:

- `scenario_id`;
- `vm`: VmImageId, initial SnapshotId, deterministic profile, machine/CPU/RAM, initial virtual clock и список разрешённых устройств;
- `target`: guest path и `binary_id | null` до проверки агентом;
- упорядоченный `actions: Action[]`.

Порядок действий и префикс являются частью смысла сценария. Два TestCase с одинаковым последним stdin, но разным префиксом имеют разные ScenarioId.

### 4.1. Action v2

Каждое действие имеет уникальный внутри TestCase `action_id` и `kind`.

| `kind` | Обязательные данные и семантика |
| --- | --- |
| `write_file` | Guest path внутри разрешённого workspace, `data_hex`, mode; host path не создаётся |
| `set_env` | `name`, `value_hex`; применяется к последующим spawn в действии |
| `spawn_process` | `process_ref`, `argv_hex[]`, `cwd`; argv[0] не выполняется через shell |
| `write_stdin` | `process_ref`, `data_hex`, `close_after`; один активный процесс с этим ref |
| `advance_clock` | `delta_ns: HexU64`; продвигает только виртуальные часы VM |
| `checkpoint` | `label`; создаёт snapshot и StateNode после завершения префикса |

`set_env` не меняет host environment и уже запущенный процесс. Неизвестное действие, отсутствующий process_ref, выход за workspace и превышение лимитов — `ContractViolation`, а не пропуск действия.

После MVP добавляются `network_input`, `device_input` и другие tagged actions. В v2 они отклоняются как `unsupported_action`; Discovery может записать `unsupported_source`, но не создаёт неисполнимое действие.

### 4.2. State graph

`StateNode` содержит:

- `state_id`, `snapshot_id`, `scenario_id`;
- `parent_state_id | null`, `action_index` и `action_id`;
- `episode_id`, `step_id` создания;
- `analysis_revision` и `effects_digest`;
- `quality=complete|partial|invalid`.

Checkpoint валиден только после успешного завершения snapshot protocol. Snapshot после timeout/QEMU error может храниться для диагностики, но не используется как проверенный родитель для новых кампаний.

Replay содержит исходный ScenarioId и префикс действий. Восстановление только последнего файла/stdin не является replay. Replay от промежуточного StateId должен периодически сравниваться с полным replay от initial snapshot.

## 5. Динамическая модель кода

`AnalysisModel` содержит `binary_id`, `analysis_revision`, analyzer/parameters, executable ranges, blocks, edges и unknown regions.

| Объект | Минимальные поля |
| --- | --- |
| `Block` | `id`, `end_elf_va`, `instruction_start_elf_vas`, `confidence=validated|speculative`, `source=static|dynamic|symbol|hint` |
| `Edge` | `from`, `kind`, `site_elf_va`, `to` для resolved; `unresolved_reason` для unresolved |
| `UnknownRegion` | start/end и `reason=undecodable|truncated_instruction|conflicting_boundaries|unexplored|unmapped_static` |

Виды рёбер: `taken`, `fallthrough`, `jump`, `call`, `continuation`, `return`, `unresolved`. Для `return|unresolved` поле `to` отсутствует; фиктивный нулевой адрес запрещён.

Перед хешированием диапазоны сортируются по start/file offset, блоки — по start ELF VA, instruction starts строго возрастают, рёбра — по from/site/kind/to, unknowns — по start/end/reason. Порядок динамического обнаружения не должен менять AnalysisRevision при одинаковой итоговой модели.

AnalysisModel может расти между episodes. Проценты покрытия разных AnalysisRevision не объединяются без общего зафиксированного знаменателя и пересопоставления. История revision сохраняется.

## 6. Episode, Step и покрытие

### 6.1. Исходы

`EpisodeResult` содержит ScenarioId, EpisodeId, backend, VM/QEMU/agent identities, общий outcome, `steps: StepResult[]`, StateNodes и errors.

`StepResult` содержит StepId, action index/id, timing, `process_created` применимо к spawn, `outcome`, coverage/effects и errors.

Исходы действия/процесса: `completed`, `exited(code)`, `signaled(signal)`, `timed_out`, `cancelled`, `unsupported_runtime`, `agent_error`, `backend_error`, `spawn_error`, `not_started`. Код 139 не заменяет доказанный signal. Ошибка agent/QEMU не выдаётся за поведение цели.

### 6.2. CoverageSnapshot

Обязательные поля:

- EpisodeId, StepId, BinaryId, MappingId, AnalysisRevision;
- `covered_blocks: BlockId[]` в каноническом порядке;
- `unmapped_guest_vas`, `unknown_overflow`;
- `quality=complete|partial|invalid` и `errors`.

Покрытие означает наблюдение входа перед первой инструкцией блока, не его завершение. Translation без execution покрытия не создаёт. Посещение двух блоков не доказывает ребро.

| Качество | Потребление |
| --- | --- |
| `complete` | Mapping/header валидны, обязательные каналы завершены без потерь; допустимы положительные и отрицательные наблюдения для instrumented validated-блоков |
| `partial` | Mapping валиден, но timeout/KILL/cancel/backend termination/overflow; объединяются только сохранённые положительные посещения |
| `invalid` | Неверные IDs/ABI/mapping/длины/bias; `covered_blocks=[]`, novelty запрещён |

Для partial/invalid обязательна машинная причина. Повреждённые raw bytes могут храниться отдельно, но не как валидные блоки.

Состояния блоков: `covered`, `not_observed`, `unknown`, `out_of_scope`. `not_observed` требует хотя бы одного complete-снимка соответствующей модели и не означает недостижимость. Partial не доказывает отсутствие. Библиотеки/ядро вне выбранного scope — out_of_scope.

## 7. Discovery и эффекты

`InterfaceHint` содержит `kind=stdin|file|env|cwd|clock|network|ipc|process`, source Episode/Step, наблюдение, `confidence=hint|confirmed|unsupported` и созданные действия. Сеть/IPC в MVP записываются как `unsupported_source` и не мутируются.

`EffectEvent` содержит EpisodeId, StepId, атрибутированный process/mapping, `kind=stdout|stderr|file_read|file_write|process|network|clock|exit|signal`, данные или digest, truncation и `attribution=confirmed|suspected|unknown`.

Эффект с `attribution!=confirmed` не повышает уровень Finding самостоятельно. Фоновая активность VM не приписывается цели без доказательства. Digest не заменяет сохранённые минимальные доказательства для controlled trigger.

## 8. Concolic DSE

### 8.1. Источники

`SourceId = { action_index, field, offset, length }` однозначно адресует байты изменяемого поля Action. `offset` и `length` — integer bytes; `field` — каноническое имя, например `stdin`, `file:/tmp/vf-work/config`, `env:MODE`, `clock_delta`.

Taint/source record дополнительно связывает SourceId с MappingId и диапазоном конкретного исполнения. Неизвестный SourceId, выход за длину поля и изменение неизменяемого VM config запрещены.

### 8.2. DseAttempt

Содержит:

- исходные EpisodeId/StepId/ScenarioId/AnalysisRevision;
- DseTargetId, condition site и желаемая ветвь;
- `sources: SourceId[]`, trace/symbolic limits и список unsupported operations;
- solver name/version, `solver_result=sat|unsat|unknown|timeout|unsupported|error`, duration и model;
- `context_patch: PatchOperation[]`;
- новый ScenarioId и concrete validation EpisodeId;
- `reached`, stop reason и errors.

`PatchOperation = { source_id, value_hex }`. Вся длина SourceId заменяется с учётом width/endian; патч не может менять другой префикс, snapshot или target.

`unsat` относится только к построенной модели и допущениям. `sat` без наблюдения целевого BlockId не считается достижением. Каждый candidate проходит общий runner, бюджет и журнал.

MVP symbolic scope — исследуемый процесс. Библиотека/ядро/QEMU вне scope обрывают или ограничивают symbolic path с явной причиной, а не молча моделируются как точные.

## 9. Findings и заключение

Уровни:

| Уровень | Необходимые доказательства |
| --- | --- |
| `static_hypothesis` | Статический блок/условие и причина интереса; нет заявления о достижимости |
| `observed_anomaly` | Конкретный Episode/Step, путь/эффект и факторы аномальности |
| `reproducible_anomaly` | Независимые повторы из проверенного snapshot с совпадающими нормализованными наблюдениями |
| `controlled_trigger` | Минимальная пара сценариев, где одно изменение включает/выключает эффект, и повторы обеих сторон |
| `dse_validated_trigger` | Controlled trigger + DseAttempt с solver model и конкретным достижением целевого BlockId |

`Finding` содержит ScenarioId префикса, action index, исходные и повторные EpisodeId, BlockId/MappingId, эффекты, DseAttemptId при наличии, minimal pair, limitations и `candidate_verdict`.

Допустимый `candidate_verdict=potential_undeclared_behavior` означает только кандидата на потенциально недекларированное поведение. Поля `malicious=true` или доказанной недекларированности в v2 нет. `anomaly_score` — объяснимое ранжирование, не вероятность вредоносности.

## 10. Кампания, бюджеты и хранение

`CampaignManifest` содержит схему, VM/snapshot/target IDs, SHA инструмента/QEMU/patches/plugins/agent/Z3, toolchain, VM profile, начальные сценарии, RNG seed, лимиты, AnalysisRevisions, счётчики и stop reason.

Раздельные бюджеты:

- `max_episodes` — попытки исполнения TestCase с фактически созданной VM;
- `max_target_execs` — запуски исследуемого процесса с `process_created=true`;
- `max_wall_time_ms` и `max_virtual_time_ns`;
- `max_solver_calls`, `max_solver_time_ms`;
- лимиты actions, bytes, RAM/disk/output и snapshots.

Ошибка до создания VM не расходует episode, ошибка до создания процесса не расходует target exec; обе расходуют wall time и журналируются. Replay внутри кампании расходует соответствующие бюджеты. Ручной replay после кампании создаёт отдельную сессию.

Хранение:

```text
runs/<campaign>/
  manifest.json
  vm/                 # descriptors, не изменяемые базовые образы
  scenarios/<sha256>.json
  episodes/<id>/      # steps, coverage, effects, bounded output
  states/             # snapshot descriptors и CoW artifacts
  analysis/<revision>.json
  dse/<attempt>.json
  findings/<id>.json
  events.jsonl
  report.json
  report.md
```

Существующий manifest запрещает перезапись. Scenario сохраняется до VM execution; candidate и ContextPatch — до concrete validation. JSON пишется atomic rename; events JSONL имеет самостоятельный объект v2 на строку; повреждённый хвост не является событием. Базовые VM images read-only, изменения только CoW.

## 11. Backend и wire protocols

Contracts v2 фиксирует логические сообщения, но не навязывает один транспорт двум backends.

### Общие требования

- Versioned magic/major/minor, явные длины, endian и overflow checks.
- EpisodeId/StepId/ScenarioId/BinaryId/MappingId/AnalysisRevision проверяются до принятия данных.
- Execution callback отличается от translation; бит/событие блока имеет прямой индекс без hash collision.
- Инициализация header публикуется после immutable IDs и offsets; runner читает финальные данные после reaping. Незавершённый header — invalid; KILL при валидном mapping — partial.
- Unknown IDs, flags, reserved bytes, truncated frame и несовместимая версия отклоняются.

### qemu-system

Snapshot descriptor и plugin/agent events должны однозначно связывать address space, mapping generation, step и coverage. Физический shared-memory/virtio protocol утверждается после VF-02; его ABI версионируется отдельно от JSON.

### qemu-user

Может использовать mmap с упрощённым single-process mapping, но обязан создавать те же логические CoverageSnapshot и MappingRecord. System-only actions возвращают `unsupported_action`.

### Guest agent

Кадр содержит версию, длину, Episode/Step, action index, payload length и SHA-256 payload. Ответ дедуплицируется по Episode/Step/request ID. Разрыв, duplicate response и превышение лимита не приводят к повторному деструктивному действию автоматически.

## 12. Обязательные проверки Contracts v2

Rust-модель должна:

- round-trip все примеры и сохранять HexU64, включая `0xffffffffffffffff`;
- повторно вычислять ScenarioId и AnalysisRevision;
- отклонять чужие SnapshotId/BinaryId/MappingId/AnalysisRevision;
- различать `not_started`, `spawn_error`, `backend_error` и поведение цели;
- не принимать invalid coverage и `sat` без concrete observation как достижение;
- проверять SourceId/ContextPatch против Action;
- требовать полный префикс для replay;
- не позволять повысить Finding без минимальной пары, повторов и DSE-доказательств;
- отклонять system-only action в qemu-user и неизвестные действия v2.

Примеры находятся в [contracts/examples/](contracts/examples/): `scenario.json`, `analysis-model.json`, `episode-result.json`, `coverage-invalid.json`, `dse-attempt.json`, `finding.json`, `campaign-manifest.json`.
