/* ==== capp.c: референс C-сервера rust-l4 (v0.8) ====
 *
 * Первый пользовательский сервер НА ЧИСТОМ C через userlib (libuserlib.a):
 * _start и l4_* — библиотека, main — приложение. Демонстрирует:
 *
 *   * стартовый протокол L4: argc/argv (имя модуля + <arg> из
 *     boot_cfg.xml + boot_state «имя=значение»);
 *   * SELF_INFO: идентификация + топология CPU;
 *   * MEM_ALLOC: страница + запись/чтение паттерна;
 *   * IOMMU (если контроллер поднят): ENUM (флаги v0.8: bit4 IRQ-ремап,
 *     bit5 крупные страницы), ATTACH(00:1f.2), MAP 2+512 стр (huge),
 *     UNMAP, IRQ_MAP/IRQ_UNMAP (IRTE), DETACH;
 *   * TASK_EXIT(0) — возврат из main.
 *
 * Сборка: scripts/build.sh (gcc -ffreestalling -nostdlib + init.ld;
 * грузится boot_cfg_c.xml как первый сервер). С QEMU:
 *   BOOT_CFG=scripts/boot_cfg_c.xml bash scripts/build.sh
 *   QEMU_IOMMU=amd|1 bash scripts/run_qemu.sh
 */

#include "l4.h"

/* Максимальная длина печатаемой argv-строки (локальный буфер). */
#define ARG_MAX 80

static void print_arg(const char *a)
{
    char buf[ARG_MAX + 2];
    unsigned i = 0;
    while (i < ARG_MAX && a[i] != '\0') {
        buf[2 + i] = a[i];
        i++;
    }
    buf[0] = ' ';
    buf[1] = ' ';
    buf[2 + i] = '\0';
    l4_puts(buf);
}

int main(int argc, char **argv)
{
    l4_puts("=== capp: first C server (userlib interop) ===");

    /* Идентификация (SELF_INFO: слова 2/3 = thread id lo/hi). */
    l4_puthex("capp: tid lo = ", (uint64_t)l4_self_info(2));
    l4_puthex("capp: tid hi = ", (uint64_t)l4_self_info(3));
    l4_puthex("capp: cpu      = ", (uint64_t)l4_self_info(4));
    l4_puthex("capp: cpu_count= ", (uint64_t)l4_self_info(5));

    /* Стартовая конфигурация: argv[0] = имя модуля, хвост = <arg> из
     * boot_cfg.xml + boot_state («имя=значение») — транзит из XML. */
    if (argc > 0) {
        l4_puts("capp: boot configuration (argv + boot_state):");
        for (int i = 0; i < argc; i++) {
            print_arg(argv[i]);
        }
    }

    /* Память: страница RW + паттерн (volatile — как у Rust-воркеров). */
    int64_t page = l4_mem_alloc(1, 0x3);
    if (page > 0) {
        volatile uint64_t *p = (volatile uint64_t *)(uintptr_t)page;
        *p = 0xCAFEBABEDEADBEEFULL;
        l4_puthex("capp: mem_alloc page  = ", (uint64_t)page);
        l4_puthex("capp: mem pattern     = ", *p);
    } else {
        l4_puthex("capp: mem_alloc failed  = ", (uint64_t)page);
    }

    /* IOMMU: сквозной проход (как init-демо, на C). */
    int64_t n = l4_iommu_enum(0xFFFFFFFFULL, 0);
    if (n <= 0) {
        l4_puts("capp: iommu: no controllers (run QEMU with -device intel-iommu|amd-iommu)");
    } else {
        uint64_t flags = (uint64_t)l4_iommu_enum(0, 0);
        uint64_t ver = (uint64_t)l4_iommu_enum(0, 1);
        l4_puts("capp: iommu: controller present, smoking v0.8 cycle");
        l4_puthex("capp: iommu flags  = ", flags);
        l4_puthex("capp: iommu version= ", ver);

        /* Attach BDF 00:1f.2 (встроенный ICH9 AHCI q35): есть и в
         * IVHD-записях AMD-Vi, и под INCLUDE_PCI_ALL Intel. */
        int64_t dev = l4_iommu_attach(0, 0, 0x1f, 2);
        if (dev < 0) {
            l4_puthex("capp: iommu ATTACH failed = ", (uint64_t)dev);
        } else {
            l4_puthex("capp: iommu dev id = ", (uint64_t)dev);

            /* MAP 2 страницы RW (4К PTE). */
            uint64_t packed = 2ULL | (3ULL << 32);
            int64_t m = l4_iommu_map(0, (uint64_t)dev, 0x10000, 0x03000000, packed);
            l4_puthex("capp: iommu map    -> ", (uint64_t)m);

            /* MAP 512 страниц 2 МиБ-выровненно — huge-лист (v0.8;
             * ядро печатает «map huge 2MiB» на консоль). */
            uint64_t packed_huge = 512ULL | (3ULL << 32);
            int64_t mh = l4_iommu_map(0, (uint64_t)dev, 0x04000000, 0x03000000,
                                      packed_huge);
            l4_puthex("capp: iommu map huge (512p) -> ", (uint64_t)mh);
            int64_t uh = l4_iommu_unmap(0, (uint64_t)dev, 0x04000000, 512);
            l4_puthex("capp: iommu unmap huge      -> ", (uint64_t)uh);

            /* IRQ-ремаппинг (v0.8): IRTE vector 0x41 -> APIC 0.
             * Возврат — handle: его драйвер кладёт в MSI-адрес. */
            int64_t h = l4_iommu_irq_map(0, (uint64_t)dev, 0x41, 0, 0);
            l4_puthex("capp: iommu irq_map handle  = ", (uint64_t)h);
            int64_t iu = -1;
            if (h > 0) {
                iu = l4_iommu_irq_unmap(0, (uint64_t)dev, (uint64_t)h);
                l4_puthex("capp: iommu irq_unmap       -> ", (uint64_t)iu);
            }

            int64_t u = l4_iommu_unmap(0, (uint64_t)dev, 0x10000, 2);
            l4_puthex("capp: iommu unmap  -> ", (uint64_t)u);
            int64_t d = l4_iommu_detach(0, (uint64_t)dev);
            l4_puthex("capp: iommu detach -> ", (uint64_t)d);

            if (m == 0 && mh == 0 && uh == 0 && h > 0 && iu == 0 &&
                u == 0 && d == 0) {
                l4_puts("capp: iommu smoke OK (map+huge+irq+unmap+detach)");
            } else {
                l4_puts("capp: iommu smoke FAILED");
            }
        }
    }

    l4_puts("capp: all demos done, exiting with code 0");
    return 0;
}
