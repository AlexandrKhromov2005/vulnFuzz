# Backlog blackbox MVP vulnFuzz

Актуализировано: **10.11.2026**. Эта редакция соответствует полносистемной архитектуре из [ROADMAP.md](../ROADMAP.md) и контрактам v2 из [CONTRACTS.md](CONTRACTS.md). Прежние карточки одиночного ELF/stdin MVP заменены; история сохранена в Git.

Приоритеты: **P0** — блокирует первый достоверный сквозной запуск; **P1** — обязательно для MVP; **P2** — после MVP. Размер: **S** — локальный результат, **M** — несколько файлов и интеграционная проверка, **L** — перед реализацией разделить на отдельные PR.

Роли: A — ELF/CFG/DSE; B — QEMU/VM/agent; C — scenario/fuzz/state graph; D — contracts/store/report/CI/интеграция. Один участник может совмещать роли.

## Текущий статус

Базовый код на `39bf206` содержит ELF loader, линейный Capstone disassembler и inspection CLI. В рамках VF-01 добавлены `src/model.rs` и `tests/contracts.rs`: Contracts v2, типизированные IDs/HexU64, строгая сериализация, канонические хеши, ContextPatch и перекрёстная валидация. Текущий набор — 23 integration tests + doctest.

Программная проверка VF-01 реализована: все семь JSON-примеров round-trip, хеши стабильны, ошибочные IDs/поля/действия отклоняются. Для полного закрытия карточки остаются ревью A/B/C/D и согласование с результатами QEMU-spike VF-02. Все остальные задачи не закрыты. Наличие части кода не засчитывается как выполнение карточки без зависимостей, успешного/ошибочного теста и интеграции.

## Порядок и интеграция

| Этап | Задачи | Демонстрация |
| --- | --- | --- |
| I0 | VF-01–04 | Контракты, QEMU/determinism spike, agent protocol, VM-фикстуры |
| I1 | VF-05–09 | Один episode: snapshot → действие → coverage → dynamic CFG → replay |
| I2 | VF-10–13 | Discovery, stateful сценарии, corpus и эффекты |
| I3 | VF-14–16 | Concolic DSE с конкретным достижением цели |
| I4 | VF-17–18 | Минимальные пары, доказательные findings, оба backend |
| I5 | VF-19–20 | Реальный CLI, эксперимент и чистая приёмка |

До I1 критичны VF-02/03/05/06; параллельно D ведёт модель/store, A — динамический CFG, C — TestCase. До воспроизводимого episode нельзя принимать stateful fuzzing и DSE как сквозной результат.

<a id="vf-01"></a>
## VF-01 — Утвердить архитектуру и Contracts v2

- **Статус:** реализация и автоматические проверки готовы; ожидаются ревью A/B/C/D и согласование с VF-02.
- **Результат:** согласованные TestCase/Action/State/Mapping/Coverage/DSE/Finding, JSON v2 и границы backend.
- **Файлы:** `ROADMAP.md`, `docs/CONTRACTS.md`, `docs/contracts/examples/*`, затем `src/model.rs`.
- **Зависимости:** нет. **P0, M, D + все роли.**
- **Приёмка:** различаются EpisodeId/StepId/StateId/MappingId/BinaryId/AnalysisRevision; SourceId адресует поле действия; Finding ссылается на префикс; partial/invalid и unsupported определены. Примеры round-trip без потери HexU64; чужие IDs отклоняются. Физический mmap не навязан system-backend.
- **Проверка:** примеры stateful trigger, ASLR mapping, DSE ContextPatch и controlled anomaly читаются Rust; канонические хеши стабильны.

<a id="vf-02"></a>
## VF-02 — Проверить pinned QEMU fork и детерминизм VM

- **Результат:** воспроизводимая сборка QEMU, минимальные патчи/plugins и решение о детерминированном профиле.
- **Файлы:** `third_party/` или зафиксированный external source, `qemu/patches/`, `qemu/plugins/`, `scripts/build-qemu.sh`, `experiments/determinism/`.
- **Зависимости:** VF-01. **P0, L, B.**
- **Приёмка:** записаны QEMU SHA/patches/toolchain; snapshots включают RAM/devices/disks. Два запуска одного сценария дают одинаковые нормализованные coverage/effects; проверены virtual clock, RNG, KILL/timeout и restore. Неподдерживаемые события явно отклоняются.
- **Проверка:** 10 повторов каждой начальной фикстуры, replay от начального и промежуточного snapshot, измерение overhead. Если детерминизм не достигнут, fuzzing не принимается.

<a id="vf-03"></a>
## VF-03 — Реализовать guest agent и безопасный control protocol

- **Результат:** Linux x86-64 agent и Rust host client для spawn/files/stdin/env/cwd/checkpoints.
- **Файлы:** `agent/`, `src/agent.rs`, `docs/AGENT_PROTOCOL.md`, `tests/agent.rs`.
- **Зависимости:** VF-01, начальный VF-02. **P0, M, B+D.**
- **Приёмка:** versioned framing, request/step IDs, hashes и лимиты; нет shell; argv/env бинарно корректны; agent сообщает PID/mappings и эффекты. Канал изолирован от цели, исходный образ не изменяется.
- **Проверка:** NUL/пустой вход, non-UTF-8 argv/path, большой вывод, разрыв канала, зависший agent, неизвестная версия и попытка path traversal.

<a id="vf-04"></a>
## VF-04 — Создать VM/ELF фикстуры и независимые оракулы

- **Результат:** `branches`, `trigger`, `time_bomb`, `env_file`, `stateful`, `benign_uncovered`, `crash_hang`, `mapping`, генератор образов и оракулы.
- **Файлы:** `tests/fixtures/`, `tests/vm/`, `tests/oracles/`, `scripts/build-fixtures.sh`.
- **Зависимости:** VF-01, VF-02, VF-03. **P0, L, A+B+D.**
- **Приёмка:** stripped PIE/non-PIE/sectionless ELF, контрольные блоки до strip, известные эффекты и stateful/time triggers. Есть отрицательные обычные редкие ветки. Образ собирается воспроизводимо; оракул не передаётся vulnFuzz.
- **Проверка:** readelf/objdump, SHA образов/QEMU/agent, поведение без фаззера, независимый replay оракула.

<a id="vf-05"></a>
## VF-05 — Собрать один детерминированный VM episode

- **Результат:** restore snapshot → agent spawn → действия → timeout/cancel → checkpoint → сохранение результата.
- **Файлы:** `src/backend/qemu_system.rs`, `src/runner.rs`, `src/episode.rs`, `tests/episode.rs`.
- **Зависимости:** VF-01–04. **P0, M, B.**
- **Приёмка:** различаются исходы цели/agent/QEMU/VM; эпизоды и запуски цели учитываются раздельно; stdout/stderr ограничены; после ошибки не остаются QEMU/процессы/CoW-ресурсы.
- **Проверка:** exit/signal/timeout/cancel/agent failure/QEMU failure, 100 restore/teardown циклов без утечек.

<a id="vf-06"></a>
## VF-06 — Сопоставить system coverage с процессом и ELF

- **Результат:** QEMU plugin, MappingId, нормализация PC и CoverageSnapshot для исследуемого процесса.
- **Файлы:** `qemu/plugins/coverage.c`, `src/mapping.rs`, `src/coverage.rs`, `tests/system_coverage.rs`; вспомогательно `src/loader.rs`.
- **Зависимости:** VF-02–05. **P0, L, B+A.**
- **Приёмка:** execution, а не translation; учитываются address space, bias и mapping generation; PID reuse не смешивает покрытие. Библиотеки/ядро out_of_scope. KILL даёт partial, malformed/foreign mapping invalid.
- **Проверка:** oracle двух путей, PIE/ASLR, exec/unload/PID reuse, дырки диапазонов, timeout/KILL и повреждённый snapshot.

<a id="vf-07"></a>
## VF-07 — Достраивать динамический CFG и AnalysisRevision

- **Результат:** стабильные BlockId, растущая модель, рёбра и unknown-области по статике и реальным трассам.
- **Файлы:** `src/dynamic_cfg.rs`, `src/disasm.rs`, `src/loader.rs`, `tests/dynamic_cfg.rs`.
- **Зависимости:** VF-01, VF-04, VF-06. **P0, M, A.**
- **Приёмка:** stripped/main не требуются; реальные PC подтверждают блоки, unresolved и конфликтующие байты не выдумываются. AnalysisRevision версионируется; повторный анализ детерминирован; сравнение покрытия имеет общий знаменатель.
- **Проверка:** objdump/oracle, данные в PF_X, invalid suffix, indirect branch, ASLR и рост модели между episodes.

<a id="vf-08"></a>
## VF-08 — Выполнить и воспроизвести TestCase с Action[]

- **Результат:** декларативный TestCase, последовательный executor, StateNode и replay префикса.
- **Файлы:** `src/scenario.rs`, `src/state_graph.rs`, `src/replay.rs`, `tests/scenario_replay.rs`.
- **Зависимости:** VF-01, VF-03, VF-05. **P0, M, C+B.**
- **Приёмка:** поддержаны все действия MVP, часы и checkpoints; StateId/lineage сохраняются; replay включает весь префикс, а не последний вход. Ускоренный replay сверяется с полным.
- **Проверка:** пустая/длинная цепочка, branching, повторное время, ошибка на середине, foreign snapshot и изменённый ScenarioId.

<a id="vf-09"></a>
## VF-09 — Соединить первый сквозной CLI и короткий отчёт

- **Результат:** команды `discover` (каркас), `run --scenario`, `replay --episode`; manifest/events/coverage/model/report.
- **Файлы:** `src/cli.rs`, `src/main.rs`, `src/store.rs`, `src/report.rs`, `tests/cli_smoke.rs`.
- **Зависимости:** VF-01, VF-05–08. **P0, M, D.**
- **Приёмка:** VM+snapshot+target передаются аргументами; один episode даёт реальный system coverage и replay; JSON v2, атомарные записи, ошибки без паники. Inspection CLI не выдаётся за этот сценарий.
- **Проверка:** чистый каталог, два backend-независимых отчёта, replay из другого cwd, существующий manifest не перезаписывается.

<a id="vf-10"></a>
## VF-10 — Автоматически обнаруживать CLI/file/env/time интерфейсы

- **Результат:** Discovery Engine с ограниченными probes и InterfaceHint → начальные TestCase.
- **Файлы:** `src/discovery.rs`, `src/probes.rs`, `tests/discovery.rs`.
- **Зависимости:** VF-08, VF-09. **P1, M, C+A.**
- **Приёмка:** probes без исходников; выявляются stdin/files/env/cwd/time; сеть/IPC помечаются unsupported_source. Каждая подсказка имеет наблюдение и не становится фактом без проверки.
- **Проверка:** env_file/time_bomb, отсутствие stdin, ложный файл, `--help`, таймаут и запрет деструктивных probes.

<a id="vf-11"></a>
## VF-11 — Мутировать цепочки действий и состояния

- **Результат:** stateful fuzzer действий, времени и snapshot lineage.
- **Файлы:** `src/scenario_mutations.rs`, `src/state_graph.rs`, `tests/stateful_fuzz.rs`.
- **Зависимости:** VF-08, VF-10. **P1, M, C.**
- **Приёмка:** параметры, вставка/удаление/перестановка, clock delta, branch от checkpoint; лимиты длины и ресурсов; детерминированный RNG. Достигается stateful trigger без зашитого сценария.
- **Проверка:** фиксированные мутации, minimization после достижения, повреждённый snapshot, пустая цепочка и бюджет.

<a id="vf-12"></a>
## VF-12 — Реализовать corpus, novelty и общий бюджет кампании

- **Результат:** content-addressed TestCase corpus, очередь и scheduler обычных/DSE-фаз.
- **Файлы:** `src/corpus.rs`, `src/campaign.rs`, `src/fuzz.rs`, `tests/campaign.rs`.
- **Зависимости:** VF-09, VF-11. **P1, M, C+D.**
- **Приёмка:** novelty по новым validated-блокам/эффектам, crash/timeout отдельно; invalid не даёт прогресс. Учитываются episodes, target execs, wall/virtual time, solver calls; происхождение и RNG сохраняются.
- **Проверка:** duplicate scenario, partial/invalid, лимиты 0/1, spawn/boot failure, cancel и воспроизводимая очередь.

<a id="vf-13"></a>
## VF-13 — Собирать поведенческие эффекты и минимальные наблюдения

- **Результат:** нормализованные stdout/stderr, files/processes/network/time events с привязкой к StepId.
- **Файлы:** `src/effects.rs`, `agent/effects.rs`, `tests/effects.rs`.
- **Зависимости:** VF-03, VF-05, VF-09. **P1, M, B+D.**
- **Приёмка:** различаются наблюдение и интерпретация; digest/полные данные имеют лимиты; фоновый шум VM не создаёт событие цели без атрибуции; unsupported эффекты видны.
- **Проверка:** одинаковый вывод при разных скрытых эффектах, file write, процесс, clock, truncation и ложная атрибуция.

<a id="vf-14"></a>
## VF-14 — Построить выборочную трассу и SourceId/taint

- **Результат:** ограниченная трасса исследуемого процесса с источниками из Action[].
- **Файлы:** `qemu/plugins/trace.c`, `src/trace.rs`, `src/symbolic.rs`, `tests/taint.rs`.
- **Зависимости:** VF-06, VF-08, VF-12. **P1, L, A+B.**
- **Приёмка:** SourceId связывает action/field/offset/length с байтами процесса; окно/инструкции/память ограничены; unsupported instructions и потеря taint видны. Библиотеки/ядро не попадают в symbolic scope MVP.
- **Проверка:** stdin/file/env/clock sources, overlap, unaligned read, unsupported operation, trace overflow и overhead.

<a id="vf-15"></a>
## VF-15 — Решать path constraints через Z3 и создавать ContextPatch

- **Результат:** bitvector constraints для выбранного jcc, solver process и преобразование модели в TestCase.
- **Файлы:** `src/path_predicate.rs`, `src/solver.rs`, `src/context_patch.rs`, `tests/solver.rs`.
- **Зависимости:** VF-14. **P1, L, A.**
- **Приёмка:** width/endian/sign корректны; sat/unsat/unknown/timeout/unsupported различены; лимиты процесса и памяти; патч меняет только разрешённые SourceId. Solver не считается конкретным доказательством.
- **Проверка:** 1/2/4/8-byte cmp, составные условия, signed/unsigned, невозможное условие, timeout, чужой SourceId и round-trip патча.

<a id="vf-16"></a>
## VF-16 — Замкнуть DSE-кампанию с конкретной валидацией

- **Результат:** выбор цели → трасса → Z3 → ContextPatch → общий runner → corpus/finding.
- **Файлы:** `src/dse.rs`, `src/campaign.rs`, `tests/dse_campaign.rs`.
- **Зависимости:** VF-12, VF-14, VF-15. **P1, M, A+C+D.**
- **Приёмка:** DSE достигает контрольного составного триггера без встроенного ответа; достижение по наблюдённому BlockId; попытки/solver budget/unsupported журналируются; неудача не зацикливает кампанию.
- **Проверка:** sat-but-not-reached, unsat, timeout, stateful prefix, time/env patch и сравнение с обычными мутациями на том же бюджете.

<a id="vf-17"></a>
## VF-17 — Формировать доказательные аномалии и replay findings

- **Результат:** минимальные пары, уровни Finding, объяснимый score, `report.json/md`, `replay --finding`.
- **Файлы:** `src/analysis.rs`, `src/minimize.rs`, `src/report.rs`, `tests/findings.rs`.
- **Зависимости:** VF-13, VF-16. **P1, M, D+A.**
- **Приёмка:** уровни от static_hypothesis до dse_validated_trigger имеют проверяемые условия; controlled trigger требует включение/выключение минимальным изменением; replay восстанавливает префикс. Нет автоматического вердикта о вредоносности.
- **Проверка:** нестабильный результат, benign редкость, одинаковый stdout/разные эффекты, нехватка бюджета и независимый replay.

<a id="vf-18"></a>
## VF-18 — Интегрировать qemu-user и общую матрицу backend

- **Результат:** быстрый ELF backend с общими CoverageSnapshot/CFG/DSE/report и обязательная CI-матрица.
- **Файлы:** `src/backend/qemu_user.rs`, `instrumentation/qemu-user/`, `tests/backend_matrix.rs`, CI.
- **Зависимости:** VF-06, VF-09, VF-16, VF-17. **P1, M, B+A+D.**
- **Приёмка:** на общей фикстуре нормализованные наблюдения совместимы; transport различия не меняют модель; system-only TestCase явно unsupported в user-mode. Ошибки QEMU не считаются целевыми.
- **Проверка:** PIE/non-PIE/stripped, file/stdin, partial/invalid, DSE trigger и сравнение system/user без смешивания несовместимых сценариев.

<a id="vf-19"></a>
## VF-19 — Провести эксперимент на VM-фикстурах и реальном CLI

- **Результат:** зафиксированный протокол, сырые данные, сравнение context fuzzing и +DSE, разбор реального CLI.
- **Файлы:** `experiments/compare/`, `experiments/real-cli/`, `docs/EVALUATION.md`.
- **Зависимости:** VF-17, VF-18. **P1, M, D+все роли.**
- **Приёмка:** одинаковые snapshots/seeds/budgets; известные оракулы только для внешней проверки; метрики coverage/time-to-trigger/solver/replay/false positives; неуспешные попытки сохранены. Реальный CLI исследуется без встроенного ответа.
- **Проверка:** повтор выбранных серий, общий знаменатель покрытия, публикация отрицательного результата и ограничений.

<a id="vf-20"></a>
## VF-20 — Принять исследовательский MVP из чистой среды

- **Результат:** README/BUILD/SUPPORTED, команды run/discover/replay, запись приёмки на SHA всех компонентов.
- **Файлы:** `README.md`, `docs/BUILD.md`, `docs/SUPPORTED.md`, `docs/MVP_ACCEPTANCE.md`.
- **Зависимости:** VF-19 и транзитивно VF-01–18. **P1, M, D + независимый проверяющий.**
- **Приёмка:** выполнены все десять критериев ROADMAP; чистая сборка Rust/QEMU/agent/Z3, обязательные backend tests, stateful+DSE демонстрация, отрицательный пример, реальный CLI и replay. Нет открытых P0/P1.
- **Проверка:** второй участник выполняет инструкции на чистой изолированной VM и сохраняет команды, коды возврата, hashes и отчёты.

## После MVP

Отдельные задачи создаются для network/IPC mutation, services и GUI, stateful protocols, DSE библиотек и ядра, других архитектур/OS, распределённых VM workers, production sandbox и долгих кампаний. Эти возможности не должны неявно считаться реализованными из-за наличия общих полей Contracts v2.

## Definition of Done

Задача закрывается после реализации, успешного и ошибочного теста, ревью, обновления документации и интеграции с реальным соседним модулем. Синтетические снимки подходят для ранних unit tests, но не заменяют QEMU/VM приёмку. Изменение контракта требует миграции схемы или явного отказа читать старую версию.
