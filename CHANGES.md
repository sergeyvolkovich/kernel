# rust-l4: изменения по версиям (workspace)

## v0.6 — полноценный SMP + IOMMU (Intel VT-d)

### Сделано

**SMP (симметричная многопроцессорность):**
- Топология из MADT (`smp::bring_up`): RSDP -> XSDT/RSDT -> APIC-таблица,
  слоты CPU не уплотняются (cpu_id = индекс всех per-CPU массивов).
- SIPI-запуск AP: трамплин real->protected->long (position-fixed блоб на
  0x8000, почтовый ящик 0x8F00+), INIT-SIPI-SIPI + поллинг MAGIC_OK.
- per-CPU состояние: GDT/TSS/IDT/MSR/FPU + LAPIC на каждом AP
  (`ap_entry64`), GS-блоки, ядровые стеки 16K на AP.
- Модель синхронизации — big kernel lock (`klock.rs`): пользователь
  исполняется на всех CPU параллельно, входы в ядро сериализованы;
  планировщик — глобальная очередь готовности + per-CPU
  квант/флаг перепланировки (GS).
- resched-IPI (VEC 0x21, чистый asm-обработчик: gs:NEED_RESCHED + EOI),
  TLB shootdown IPI (VEC 0x22, битмап ACK), halt-IPI паники (VEC 0x23).
- Release-протокол: APы паркуются до окончания kinit
  (`X86Platform::run` -> `release_aps`).
- Демо в init: S3 SMP-стресс — поток на CPU, разделяемый счётчик,
  yield-миграции; гистограмма «на каких CPU исполнялся».

**IOMMU (Intel VT-d):**
- Парсинг DMAR (`find_table` -> `DmarTable` -> DRHD), драйвер
  `backend/vtd.rs`: root/context-таблицы, домены, SSPT (4 уровня,
  AGAW48), queued invalidations, включение DMA-ремаппинга.
- Сервис сисколов IOMMU_* (группа 0x80): ENUM/ATTACH/MAP/UNMAP/DETACH
  поверх `IommuService`; установка платформой в `run()`.
- Демо в init: S2 IOMMU smoke — ENUM -> ATTACH(00:01.0) ->
  MAP(2 стр RW) -> повторный MAP (EEXIST) -> UNMAP -> DETACH.

### Исправленные баги

1. **ICR shorthand перепутаны** (`lapic.rs`): код использовал
   `0b10 << 18` для «всем кроме себя», а по спеке (SDM Vol.3 10.6)
   `0b10` = *all including self*, `0b11` = *all excluding self*.
   Сам-IPI отправителю становился pending на IF=0-участках, AP не
   просыпался из парковки по resched-IPI. Константы поменяны местами.
2. **Связка VT-d <-> сисколы**: `init_and_install` помечал VTD0 готовым,
   но НЕ вызывал `install_iommu_service` — SERVICE=None, все IOMMU_*
   отвечали ENOSYS (init видел «no controllers»).
3. **GCMD.ENABLE гасил QIE** (`vtd.rs`): каждый бит GCMD — запрос на
   изменение; запись ENABLE без бита QIE означала «выключи QI» — QEMU
   останавливал обработку очереди инвалидаций (vtd_inv_qi_enable 0),
   первый ATTACH таймаутил (EIO). Теперь пишется `ENABLE|QIE`
   с проверкой TES **и** QIES.
4. ABI-выравнивание стека в ассемблерных точках входа
   (syscall/timer/fault/shootdown: якорь rbx + and rsp,-16);
   трамплин: `sub rsp, 8` перед входом в ядро.
5. Баг v0.5 в `syscall_c`: двойное продвижение rip (+2) при вытеснении —
   SMP-вытеснение проявляло как декод мусора (#PF на запись в RX).
6. `idle_loop` до установки glue (fatal-пути загрузки) — честное
   сообщение и сон вместо паники.

### Известные ограничения (задокументировано)

- QEMU 10.0 (MTTCG): доставка IPI остановленному vCPU ненадёжна —
  run-скрипт использует `-accel tcg,thread=single` (на KVM/железе
  проблемы нет).
- IRQ-ремаппинг VT-d не реализован (запуск с `intremap=off`);
  пер-процессорных очередей планировщика нет (одна глобальная под BKL);
  shrink фасадов не освобождает промежуточные таблицы (v0.6 без
  рефкаунтов страниц таблиц).

### Числа

- 139 тестов зелёные (kernel 125 + bootcfg 9 + boot_info 5), сборка
  workspace чистая; rustfmt применён.
- QEMU end-to-end зелёный в трёх конфигурациях:
  SMP=2 (без IOMMU), IOMMU+SMP=2, IOMMU+SMP=4 (3 воркера,
  0xc000 инкрементов == ожидаемым, lost updates = 0).
