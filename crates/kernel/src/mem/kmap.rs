// ==== KMAP: таблица адресного пространства ядра ====
//
// Упорядоченный реестр [`KernelRegion`]: непересекающиеся виртуальные
// диапазоны ядра + политика изоляции ([`IsolationPolicy`]). Это учёт и
// валидация, НЕ аллокатор: таблица не выделяет память и не строит таблицы
// страниц. Фактическое отображение выполняет arch-бекенд — трейт
// [`KMAPInterface`] (см. `hal::traits::kmap`), который фасады крейта
// дёргают при создании UMAP.
//
// Свойства таблицы:
//   - регионы хранятся отсортированными по `v_base` (бинарный поиск на
//     всех горячих путях: вставка, `find_by_vaddr`, `overlaps`);
//   - инвариант непересечения поддерживается при вставке и проверяется
//     в debug-режиме;
//   - имена регионов уникальны (аудит: снятие/поиск по имени однозначны).
//
// Типичный сценарий: платформенный код при старте заполняет таблицу
// (образ ядра, physmap, MMIO, трамплин входа, vdso-аналог), задаёт
// политику изоляции по данным CPU и передаёт таблицу менеджеру
// ([`crate::mem::MemoryManager::install_kmap`]). Дальше каждый создаваемый
// UMAP-фасад получает ядро «как положено» по политике — с учётом
// Meltdown/Spectre (KPTI) или целиком (supervisor-only) на здоровом железе.

use alloc::vec::Vec;

pub use crate::hal::traits::kmap::{
    IsolationPolicy, KMAPInterface, KernelRegion, KernelRegionKind,
};
use crate::hal::traits::mmap::{MemErrorCode, PAGE_SIZE, VirtualADDR};

/// Таблица адресного пространства ядра (KMAP).
#[derive(Clone, Debug)]
pub struct KMap {
    /// Политика изоляции: что из таблицы попадает в пользовательские
    /// таблицы страниц создаваемых фасадов.
    policy: IsolationPolicy,
    /// Регионы, отсортированные по `v_base`; инвариант — без пересечений.
    regions: Vec<KernelRegion>,
}

impl KMap {
    /// Пустая таблица с заданной политикой изоляции.
    pub const fn new(policy: IsolationPolicy) -> Self {
        Self {
            policy,
            regions: Vec::new(),
        }
    }

    /// Политика изоляции таблицы.
    #[inline]
    pub const fn policy(&self) -> IsolationPolicy {
        self.policy
    }

    /// Сменить политику изоляции (влияет только на фасады, созданные после).
    #[inline]
    pub fn set_policy(&mut self, policy: IsolationPolicy) {
        self.policy = policy;
    }

    /// Вставить регион с проверкой пересечений и уникальности имени.
    ///
    /// Ошибки: пересечение с существующим диапазоном — [`MemErrorCode::AlreadyMapped`];
    /// дубликат имени / переполнение конца диапазона — [`MemErrorCode::InvalidArgument`].
    pub fn add(&mut self, region: KernelRegion) -> Result<(), MemErrorCode> {
        let end = region.end().ok_or(MemErrorCode::InvalidArgument(
            "kernel region range overflows",
        ))?;

        // Имя уникально: снятие/поиск по имени обязаны быть однозначными.
        if self.regions.iter().any(|r| r.name() == region.name()) {
            return Err(MemErrorCode::InvalidArgument(
                "duplicate kernel region name",
            ));
        }

        // Точка вставки: первый индекс с v_base >= region.v_base.
        let idx = self
            .regions
            .partition_point(|r| r.v_base() < region.v_base());

        // Сосед слева начинается не позже: пересечение, только если он
        // дотягивается концом до базы нового региона.
        if let Some(prev) = self.regions.get(idx.wrapping_sub(1)) {
            if let Some(prev_end) = prev.end() {
                if prev_end > region.v_base() {
                    return Err(MemErrorCode::AlreadyMapped);
                }
            }
        }
        // Сосед справа (и все дальше) начинаются не раньше базы нового:
        // пересечение, только если новый дотягивается до соседа.
        if let Some(next) = self.regions.get(idx) {
            if next.v_base() < end {
                return Err(MemErrorCode::AlreadyMapped);
            }
        }

        self.regions.insert(idx, region);
        Ok(())
    }

    /// Вставить пачку регионов. При отказе на любом элементе полностью
    /// откатывает вставки ЭТОГО вызова (стиль откатов крейта), ошибка —
    /// от неудавшегося элемента.
    ///
    /// Откат — поимённый (не `truncate`): вставки идут в произвольные
    /// позиции сортированной таблицы, «последние N» не равны «вставленным
    /// в этом вызове».
    pub fn add_all<I: IntoIterator<Item = KernelRegion>>(
        &mut self,
        regions: I,
    ) -> Result<(), MemErrorCode> {
        let mut added: Vec<KernelRegion> = Vec::new();
        for region in regions {
            match self.add(region) {
                Ok(()) => added.push(region),
                Err(e) => {
                    // Откат: снимаем ровно то, что вставили в этом вызове.
                    // Имена уникальны, записи иммутабельны — remove по имени
                    // однозначен. Снятие безусловное (не debug_assert!):
                    // откат обязан работать и в release. Отказ невозможен:
                    // регион вставлен этим же вызовом.
                    for r in added {
                        let _ = self.remove(r.name());
                    }
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Снять регион по имени; возвращает снятую запись.
    ///
    /// Ошибка [`MemErrorCode::NotFound`], если региона с таким именем нет.
    /// Учтите: снятие из таблицы НЕ снимает уже поставленные фасадами
    /// отображения — они управляются на уровне фасадов
    /// ([`crate::mem::ufacade::UFacade::unmap_kernel_regions`]).
    pub fn remove(&mut self, name: &str) -> Result<KernelRegion, MemErrorCode> {
        let pos = self
            .regions
            .iter()
            .position(|r| r.name() == name)
            .ok_or(MemErrorCode::NotFound)?;
        Ok(self.regions.remove(pos))
    }

    /// Все регионы таблицы (отсортированы по базовому адресу).
    #[inline]
    pub fn regions(&self) -> &[KernelRegion] {
        &self.regions
    }

    /// Число регионов в таблице.
    #[inline]
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Пуста ли таблица.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Регионы, обязанные попасть в пользовательскую таблицу страниц
    /// при текущей политике изоляции (фильтр KPTI / полного ядра).
    #[inline]
    pub fn user_visible(&self) -> impl Iterator<Item = &KernelRegion> {
        let policy = self.policy;
        self.regions
            .iter()
            .filter(move |r| policy.visible_in_user_tables(r.kind()))
    }

    /// Регион, содержащий адрес (бинарный поиск по базам).
    pub fn find_by_vaddr(&self, v: VirtualADDR) -> Option<&KernelRegion> {
        // Кандидат — регион с наибольшей базой, не превышающей адрес.
        let idx = self.regions.partition_point(|r| r.v_base() <= v);
        self.regions
            .get(idx.wrapping_sub(1))
            .filter(|r| r.contains(v))
    }

    /// Пересекается ли диапазон `[v_base, v_base + pages * PAGE_SIZE)` с
    /// таблицей. Используется фасадами: пользовательский диапазон не имеет
    /// права задевать ядро.
    ///
    /// Переполнение конца диапазона трактуется консервативно как пересечение
    /// (проверить отсутствие пересечения невозможно — вызывающий обязан
    /// отказаться от такого диапазона).
    pub fn overlaps(&self, v_base: VirtualADDR, pages_count: usize) -> bool {
        let Some(end) = v_base.offset(pages_count.saturating_mul(PAGE_SIZE)) else {
            return true;
        };
        // Регион с наибольшей базой < end — единственный кандидат: соседние
        // регионы не пересекаются между собой, значит более ранние кончаются
        // не позже него, а более поздние начинаются не раньше `end`.
        self.regions
            .get(
                self.regions
                    .partition_point(|r| r.v_base() < end)
                    .wrapping_sub(1),
            )
            .and_then(KernelRegion::end)
            .is_some_and(|r_end| r_end > v_base)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::hal::traits::mmap::MMAPMemoryFlags;

    /// Канонические адреса для тестов: ядро в высокой половине.
    const KTEXT: usize = 0xFFFF_8000_0000_0000;
    const KDATA: usize = 0xFFFF_9000_0000_0000;
    const TRAMPOLINE: usize = 0xFFFF_C000_0000_0000;
    const VDSO: usize = 0x0000_7000_0000_0000;

    fn ktext_region() -> KernelRegion {
        KernelRegion::kernel("ktext", VirtualADDR(KTEXT), 16, MMAPMemoryFlags::RX).unwrap()
    }

    fn trampoline_region() -> KernelRegion {
        KernelRegion::entry_trampoline(
            "trampoline",
            VirtualADDR(TRAMPOLINE),
            1,
            MMAPMemoryFlags::RX,
        )
        .unwrap()
    }

    #[test]
    fn add_find_and_lookup() {
        let mut kmap = KMap::new(IsolationPolicy::UserTableIsolation);
        kmap.add(ktext_region()).unwrap();
        kmap.add(trampoline_region()).unwrap();
        // Вставка «не по порядку» обязана отсортироваться.
        kmap.add(
            KernelRegion::kernel("kdata", VirtualADDR(KDATA), 8, MMAPMemoryFlags::RW).unwrap(),
        )
        .unwrap();

        assert_eq!(kmap.len(), 3);
        // Порядок: vdso-диапазон не добавлен, поэтому ktext < kdata < trampoline
        // по базам (0xFFFF_8000 < 0xFFFF_9000 < 0xFFFF_C000).
        let bases: Vec<usize> = kmap
            .regions()
            .iter()
            .map(|r| r.v_base().as_usize())
            .collect();
        assert_eq!(
            bases,
            vec![KTEXT, KDATA, TRAMPOLINE],
            "таблица обязана быть отсортирована"
        );

        // Поиск: попадание внутрь региона (не в базу).
        let found = kmap
            .find_by_vaddr(VirtualADDR(KTEXT + 3 * PAGE_SIZE))
            .expect("адрес внутри ktext обязан находиться");
        assert_eq!(found.name(), "ktext");

        // Поиск: база региона.
        assert_eq!(
            kmap.find_by_vaddr(VirtualADDR(KDATA)).unwrap().name(),
            "kdata"
        );

        // Поиск: последний адрес региона (end - 1) найдётся, end — нет.
        let kdata = kmap.find_by_vaddr(VirtualADDR(KDATA)).unwrap();
        let kdata_end = kdata.end().unwrap().as_usize();
        assert!(kmap.find_by_vaddr(VirtualADDR(kdata_end - 1)).is_some());
        assert!(
            kmap.find_by_vaddr(VirtualADDR(kdata_end)).is_none(),
            "end не принадлежит региону"
        );

        // Промах между регионами и до/после всех.
        assert!(kmap.find_by_vaddr(VirtualADDR(0x1000)).is_none());
        assert!(kmap.find_by_vaddr(VirtualADDR(usize::MAX)).is_none());
    }

    #[test]
    fn add_rejects_overlaps() {
        let mut kmap = KMap::new(IsolationPolicy::UserTableIsolation);
        kmap.add(ktext_region()).unwrap();

        // Полное вложение в существующий регион.
        let inside = KernelRegion::kernel(
            "inside",
            VirtualADDR(KTEXT + PAGE_SIZE),
            2,
            MMAPMemoryFlags::RX,
        );
        assert!(matches!(
            kmap.add(inside.unwrap()),
            Err(MemErrorCode::AlreadyMapped)
        ));

        // Частичное пересечение слева (начало до базы, конец внутри).
        let left = KernelRegion::kernel(
            "left",
            VirtualADDR(KTEXT - PAGE_SIZE),
            2,
            MMAPMemoryFlags::RX,
        );
        assert!(matches!(
            kmap.add(left.unwrap()),
            Err(MemErrorCode::AlreadyMapped)
        ));

        // Частичное пересечение справа.
        let right = KernelRegion::kernel(
            "right",
            VirtualADDR(KTEXT + 15 * PAGE_SIZE),
            4,
            MMAPMemoryFlags::RX,
        );
        assert!(matches!(
            kmap.add(right.unwrap()),
            Err(MemErrorCode::AlreadyMapped)
        ));

        // Прилегающий регион (end == база соседа) — НЕ пересечение.
        let mut adjacent = KMap::new(IsolationPolicy::UserTableIsolation);
        adjacent.add(ktext_region()).unwrap();
        adjacent
            .add(
                KernelRegion::kernel(
                    "adjacent",
                    VirtualADDR(KTEXT + 16 * PAGE_SIZE),
                    4,
                    MMAPMemoryFlags::RX,
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(adjacent.len(), 2, "прилегающие регионы допустимы");
    }

    #[test]
    fn add_rejects_duplicate_names_and_bad_geometry() {
        let mut kmap = KMap::new(IsolationPolicy::UserTableIsolation);
        kmap.add(ktext_region()).unwrap();

        // Дубликат имени при непересекающемся диапазоне.
        let other_base = VirtualADDR(KTEXT + 64 * PAGE_SIZE);
        let dup = KernelRegion::kernel("ktext", other_base, 4, MMAPMemoryFlags::RX).unwrap();
        assert!(
            matches!(
                kmap.add(dup),
                Err(MemErrorCode::InvalidArgument(
                    "duplicate kernel region name"
                ))
            ),
            "имена обязаны быть уникальны"
        );

        // Ноль страниц.
        let zero = KernelRegion::kernel("zero", other_base, 0, MMAPMemoryFlags::RX).unwrap_err();
        assert!(matches!(zero, MemErrorCode::InvalidArgument(_)));

        // Невыровненная база.
        let unaligned = KernelRegion::kernel(
            "unaligned",
            VirtualADDR(other_base.as_usize() + 8),
            4,
            MMAPMemoryFlags::RX,
        )
        .unwrap_err();
        assert!(matches!(unaligned, MemErrorCode::Unaligned));

        // W^X: WRITABLE | EXECUTABLE отвергается общей валидацией флагов.
        let wx = KernelRegion::kernel(
            "wx",
            other_base,
            4,
            MMAPMemoryFlags::WRITABLE | MMAPMemoryFlags::EXECUTABLE,
        )
        .unwrap_err();
        assert!(matches!(wx, MemErrorCode::InvalidArgument(_)));

        // Записываемый трамплин — прямой запрет политики KPTI.
        let writable_trampoline = KernelRegion::entry_trampoline(
            "bad-trampoline",
            VirtualADDR(TRAMPOLINE),
            1,
            MMAPMemoryFlags::RW,
        )
        .unwrap_err();
        assert!(matches!(
            writable_trampoline,
            MemErrorCode::InvalidArgument(_)
        ));
    }

    #[test]
    fn add_all_rolls_back_on_failure() {
        let mut kmap = KMap::new(IsolationPolicy::UserTableIsolation);
        kmap.add(ktext_region()).unwrap();

        // Пачка из трёх регионов, второй пересекается с уже существующим
        // ktext (база до ktext, конец внутри) — вся пачка откатывается.
        let batch = [
            KernelRegion::kernel("a", VirtualADDR(0x1000), 1, MMAPMemoryFlags::RW).unwrap(),
            KernelRegion::kernel("b", VirtualADDR(KTEXT - PAGE_SIZE), 2, MMAPMemoryFlags::RX)
                .unwrap(),
            KernelRegion::kernel("c", VirtualADDR(0x2000), 1, MMAPMemoryFlags::RW).unwrap(),
        ];
        let err = kmap.add_all(batch).unwrap_err();
        assert!(matches!(err, MemErrorCode::AlreadyMapped));
        assert_eq!(kmap.len(), 1, "откат обязана убрать регионы этой пачки");
        assert!(
            kmap.find_by_vaddr(VirtualADDR(0x1000)).is_none(),
            "\"a\" откачен"
        );
        assert!(
            kmap.find_by_vaddr(VirtualADDR(0x2000)).is_none(),
            "\"c\" не вставлялся"
        );
        assert!(
            kmap.find_by_vaddr(VirtualADDR(KTEXT)).is_some(),
            "прежний регион жив"
        );

        // Корректная пачка вставляется целиком.
        let ok_batch = [
            KernelRegion::kernel("a", VirtualADDR(0x1000), 1, MMAPMemoryFlags::RW).unwrap(),
            KernelRegion::user_shared("vdso", VirtualADDR(VDSO), 4, MMAPMemoryFlags::RO).unwrap(),
        ];
        kmap.add_all(ok_batch).unwrap();
        assert_eq!(kmap.len(), 3);
    }

    #[test]
    fn tlb_global_rules() {
        // GLOBAL разрешён для ядровых регионов (образ ядра одинаков во всех
        // пространствах; при MapFullKernel переживает смену тегов).
        let gk = KernelRegion::kernel(
            "ktext-g",
            VirtualADDR(KTEXT),
            4,
            MMAPMemoryFlags::RX | MMAPMemoryFlags::GLOBAL,
        )
        .unwrap();
        assert!(gk.flags().contains(MMAPMemoryFlags::GLOBAL));

        // GLOBAL + трамплин допустим: трамплин одинаков у всех процессов и
        // доступен из user-таблиц при KPTI; пригодность для железа решает бекенд.
        KernelRegion::entry_trampoline(
            "tramp-g",
            VirtualADDR(TRAMPOLINE),
            1,
            MMAPMemoryFlags::RX | MMAPMemoryFlags::GLOBAL,
        )
        .unwrap();

        // GLOBAL + UserShared — прямой запрет (права/содержимое user-страниц
        // пространство-зависимы; глобальные записи переживают теги).
        let bad = KernelRegion::user_shared(
            "vdso-g",
            VirtualADDR(VDSO),
            2,
            MMAPMemoryFlags::READABLE | MMAPMemoryFlags::GLOBAL,
        )
        .unwrap_err();
        assert!(matches!(bad, MemErrorCode::InvalidArgument(_)));

        // GLOBAL без прав R/W/X не проходит общую валидацию флагов.
        let no_perms =
            KernelRegion::kernel("np", VirtualADDR(KTEXT), 4, MMAPMemoryFlags::GLOBAL).unwrap_err();
        assert!(matches!(no_perms, MemErrorCode::InvalidArgument(_)));
    }

    #[test]
    fn policy_switch_helpers() {
        // KPTI: переключение таблиц и теги нужны.
        assert!(IsolationPolicy::UserTableIsolation.requires_table_switch());
        assert!(IsolationPolicy::UserTableIsolation.requires_asid_pair());
        // Полное ядро: ни того, ни другого.
        assert!(!IsolationPolicy::MapFullKernel.requires_table_switch());
        assert!(!IsolationPolicy::MapFullKernel.requires_asid_pair());
        assert!(IsolationPolicy::conservative().requires_table_switch());
    }

    #[test]
    fn remove_by_name() {
        let mut kmap = KMap::new(IsolationPolicy::UserTableIsolation);
        kmap.add(ktext_region()).unwrap();

        let removed = kmap.remove("ktext").unwrap();
        assert_eq!(removed.name(), "ktext");
        assert!(kmap.is_empty());

        assert!(matches!(kmap.remove("ktext"), Err(MemErrorCode::NotFound)));
    }

    #[test]
    fn user_visible_depends_on_policy() {
        let mut kmap = KMap::new(IsolationPolicy::UserTableIsolation);
        kmap.add_all([
            ktext_region(),
            trampoline_region(),
            KernelRegion::user_shared("vdso", VirtualADDR(VDSO), 4, MMAPMemoryFlags::RO).unwrap(),
        ])
        .unwrap();

        // KPTI: только трамплин и разделяемые данные (порядок — по базам:
        // vdso в низкой половине, ktext/trampoline — в высокой).
        let kpti: Vec<&str> = kmap.user_visible().map(|r| r.name()).collect();
        assert_eq!(
            kpti,
            vec!["vdso", "trampoline"],
            "Kernel-регионы скрыты при KPTI"
        );

        // Здоровое железо: виден весь набор.
        kmap.set_policy(IsolationPolicy::MapFullKernel);
        let full: Vec<&str> = kmap.user_visible().map(|r| r.name()).collect();
        assert_eq!(full, vec!["vdso", "ktext", "trampoline"]);
        assert_eq!(kmap.policy(), IsolationPolicy::MapFullKernel);

        // Переключение политики обратно действует сразу на новые фасады.
        kmap.set_policy(IsolationPolicy::conservative());
        assert_eq!(kmap.user_visible().count(), 2);
    }

    #[test]
    fn overlaps_covers_all_shapes() {
        let mut kmap = KMap::new(IsolationPolicy::UserTableIsolation);
        // Два региона с зазором: [KTEXT .. +4p) и [KDATA .. +2p).
        kmap.add(
            KernelRegion::kernel("ktext", VirtualADDR(KTEXT), 4, MMAPMemoryFlags::RX).unwrap(),
        )
        .unwrap();
        kmap.add(
            KernelRegion::kernel("kdata", VirtualADDR(KDATA), 2, MMAPMemoryFlags::RW).unwrap(),
        )
        .unwrap();

        // Точное попадание в регион.
        assert!(kmap.overlaps(VirtualADDR(KTEXT), 4));
        // Начало внутри, конец за концом региона.
        assert!(kmap.overlaps(VirtualADDR(KTEXT + 2 * PAGE_SIZE), 8));
        // Конец совпадает с базой региона (частичное пересечение слева).
        assert!(kmap.overlaps(VirtualADDR(KTEXT - PAGE_SIZE), 2));
        // Диапазон накрывает ОБА региона и зазор.
        assert!(kmap.overlaps(VirtualADDR(KTEXT), KDATA - KTEXT + PAGE_SIZE));
        // Одностраничные диапазоны в зазоре — чисто.
        assert!(!kmap.overlaps(VirtualADDR(KTEXT + 5 * PAGE_SIZE), 1));
        // До первого и после последнего региона.
        assert!(!kmap.overlaps(VirtualADDR(0x1000), 2));
        let last_end = kmap.regions().last().unwrap().end().unwrap().as_usize();
        assert!(!kmap.overlaps(VirtualADDR(last_end), 8));
        // Пустой пользовательский диапазон (0 страниц): конец == база;
        // база вне ядра — пересечения нет.
        assert!(!kmap.overlaps(VirtualADDR(0x1000), 0));
        // Пустой диапазон, но база ВНУТРИ ядра — точка пересекается.
        assert!(kmap.overlaps(VirtualADDR(KTEXT + PAGE_SIZE), 0));
    }
}
