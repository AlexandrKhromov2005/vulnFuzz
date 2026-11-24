# VF-02: детерминированный QEMU spike

Актуализировано: **19.11.2026**. Этот документ фиксирует только проверенный срез VF-02; полная приёмка карточки ещё не выполнена.

## Закреплённый источник и сборка

`qemu/source.lock` задаёт официальный репозиторий QEMU, тег `v9.2.1` и коммит `cac3fb4414778eab741a5e58ca0a30f1edc9528a`. `scripts/build-qemu.sh` клонирует источник, проверяет точный `HEAD`, отказывается перезаписывать локальные изменения, применяет только патчи из `qemu/patches/series` и собирает x86-64 system/user targets с TCG plugins. Единственный текущий патч — upstream `34febb2831ea51345fb853ee0f11bbbd5292dd6e` из v9.2.2: он устраняет конфликт `struct sched_attr` с glibc 2.41 и не меняет runtime-логику.

```sh
QEMU_JOBS=4 scripts/build-qemu.sh
```

Сборка использует `SOURCE_DATE_EPOCH` из коммита, фиксированные locale/TZ и `--with-pkgversion=vulnFuzz-cac3fb441477`. Компилятор и версии инструментов записываются в `build/qemu/provenance.txt`. Хостовый toolchain пока не закреплён контейнером, поэтому бит-в-бит воспроизводимость на разных машинах не заявляется.

## Проверенный профиль

Spike использует `pc-i440fx-9.2`, `qemu64`, одну vCPU, TCG, 16 MiB RAM, `icount shift=0,align=off`, фиксированный RTC и `clock=vm`. Неявные устройства, display, serial/parallel, monitor и сеть отключены. Диск подключается через `blkreplay`; запись и replay используют одинаковые аргументы, кроме `rr=record|replay`.

`icount sleep=off` в профиль не входит: на этой boot-фикстуре такое сочетание оставляет BIOS в ожидании таймера и запись не завершается. Для production VM это ограничение должно проверяться отдельно, а не скрываться увеличением таймаута.

Boot-сектор читает второй сектор через BIOS и выводит `vf-disk-ok\n` в `debugcon`. `isa-debug-exit` завершает запись с кодом 1; replay того же журнала на системном QEMU завершался с кодом 0 или 1 при одинаковом эффекте. Поэтому для replay допускаются оба кода, а оракулом служит только нормализованный эффект, не transport/debug exit status. Другие коды, timeout и неверный эффект отклоняются. Таймаут уничтожает всю процессную группу QEMU.

## Snapshot spike

`snapshot_replay.py` использует QMP и отдельную staged boot-фикстуру. Запись начинается с `rrsnapshot=initial`; после успешной записи второго сектора в CoW-overlay и маркера `vf-stage-1\n` VM останавливается и сохраняется `mid`. После продолжения гость читает изменённый сектор и выводит `vf-stage-2\n`.

Для каждого replay используется отдельная копия записанного overlay. Replay из `initial` должен повторить изменение диска и оба маркера; replay из `mid` — вывести только второй маркер. `snapshot=on` в этом эксперименте запрещён: snapshots RAM/devices сохраняются вместе с состоянием qcow2, а базовый образ проверяется по SHA-256. Ошибки QMP, отсутствие снапшотов, неправильный эффект и преждевременный выход процесса отклоняются.

## Команды и результат

```sh
python3 -m unittest discover -s experiments/determinism -p 'test_*.py' -v
experiments/determinism/run.py --work-dir target/vf02-system --iterations 10

# После сборки pinned QEMU:
experiments/determinism/run.py \
  --qemu build/qemu/qemu-system-x86_64 \
  --qemu-img build/qemu/qemu-img \
  --work-dir target/vf02-pinned \
  --iterations 10 --require-pinned

experiments/determinism/snapshot_replay.py \
  --qemu build/qemu/qemu-system-x86_64 \
  --qemu-img build/qemu/qemu-img \
  --work-dir target/vf02-snapshots \
  --iterations 10 --require-pinned
```

19.11.2026 на системном QEMU 9.2.1 (`Debian 1:9.2.1+ds-1ubuntu5.2`, SHA-256 `/usr/bin/qemu-system-x86_64` = `18f4d767e5ad356d8f76d2ea57ed3d99409b800043002e28ef35d472a7f05371`) выполнены 10 независимых циклов record + replay. Все 20 запусков дали ожидаемый эффект; каждый replay совпал с записью. SHA-256 базового qcow2 до и после серии одинаков: `25f6b2bab1c3667e4d488297807a74b3a69911d7e69e6c9d0e132ee5767e6d94`. В финальной системной серии среднее wall time запуска 629.4 ms, диапазон 452–956 ms; серия шла параллельно с компиляцией QEMU и не является измерением production overhead.

Затем та же серия из 10 циклов прошла с `--require-pinned` на собранном QEMU: SHA-256 system binary `86e5079c2210bc8117cf0f93e3e96608abb8c1f409466000e5dddff89e22d65b`, qemu-img `fc2778f3800a53ff6be8ff1affbb8c2068416b20445731a494676959b7d5d1cb`. Все эффекты совпали, базовый SHA не изменился, среднее wall time 480.1 ms при диапазоне 409–589 ms. Точные версии компилятора, Make/Ninja/Python, submodules и hashes патчей находятся в `build/qemu/provenance.txt` после локальной сборки.

Snapshot spike на том же pinned QEMU также прошёл 10 циклов. Initial replay 10/10 повторил оба маркера и изменение диска; mid replay 10/10 выдал только `vf-stage-2\n`. SHA-256 базового образа остался `615c2a389e15f1ae48a3af081bab72b520ecdeded774d5c9897fa9986c52561d`. Среднее wall time 30 VM-процессов — 3967.3 ms, диапазон 3593–4353 ms. Отчёт содержит список snapshots, SHA overlay/replay log и наблюдения каждого процесса.

Скрипт сохраняет `report.json` с версиями и SHA QEMU/qemu-img, версиями assembler/objcopy, фактическими аргументами профиля, эффектами, кодами выхода, wall time и SHA replay-логов. Независимые записи могут иметь разные replay-логи: критерием являются нормализованные наблюдения, а не равенство этих файлов. Существующий work directory не перезаписывается. `--require-pinned` отклоняет системный QEMU.

## Что ещё блокирует VF-02

- повторение pinned-сборки и серий на чистой среде;
- coverage plugin и сравнение нормализованных coverage, не только `debugcon`;
- guest effects, `advance_clock`, controlled RNG и явное отклонение неподдерживаемых устройств/событий;
- timeout/cancel/restore на уровне runner и измерение overhead на Linux VM;
- полноценные VM-фикстуры VF-04 и решение по production deterministic profile.

До закрытия этих пунктов spike не является доказательством детерминизма кампании и не разблокирует приёмку fuzzing.
