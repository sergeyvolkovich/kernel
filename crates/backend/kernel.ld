/* ==== kernel.ld: образ ядра x86_64 (high-half -2GiB) ====
 *
 * _start обязан быть НУЛЁВЫМ смещением образа (заглушка прыгает на
 * KERNEL_PHYS_BASE): .text.boot (head.S) — первый.
 * __kernel_image_len — точная длина образа для head.S (2MiB-маппинг).
 */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

KERNEL_LINK_BASE = 0xFFFFFFFF81000000;

SECTIONS
{
    . = KERNEL_LINK_BASE;
    __kernel_start = .;

    .text : ALIGN(4K)
    {
        KEEP(*(.text.boot))
        *(.text .text.*)
    }

    .rodata : ALIGN(4K)
    {
        *(.rodata .rodata.*)
    }

    /* Трамплин AP (SMP v0.6): блоб с фикс. смещениями внутри страницы
     * (копируется на физику 0x8000 в smp::bring_up). Смещения стадий
     * — протокол arch::boot::trampoline: 16-бит @0x000, 32-бит @0x100,
     * 64-бит @0x200, мини-GDT @0x800, lgdt-дескриптор @0xF00. */
    .trampoline : ALIGN(4K)
    {
        __tramp_start = .;
        KEEP(*(.tramp16))
        . = __tramp_start + 0x100;
        KEEP(*(.tramp32))
        . = __tramp_start + 0x200;
        KEEP(*(.tramp64))
        . = __tramp_start + 0x800;
        KEEP(*(.trampgdt))
        . = __tramp_start + 0xF00;
        KEEP(*(.trampdesc))
        __tramp_end = .;
    }

    .data : ALIGN(4K)
    {
        *(.data .data.*)
    }

    .bss : ALIGN(4K)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    . = ALIGN(4K);
    __kernel_end = .;

    /* Точная длина образа (head.S: 2MiB-страницы high-half). */
    __kernel_image_len = __kernel_end - __kernel_start;

    /DISCARD/ :
    {
        *(.eh_frame*)
        *(.note*)
        *(.comment*)
        *(.gcc_except_table*)
    }
}

/* Блоб трамплина обязан влезть в страницу 0x8000 (почтовый ящик
 * 0x8F00+ — часть блоба: дескриптор lgdt лежит НА границе 0xF00). */
ASSERT(__tramp_end - __tramp_start < 0x1000, "trampoline blob overflows AP page")
