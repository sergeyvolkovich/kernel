/* ==== init.ld: пользовательский ELF init-сервера ====
 *
 * Статический freestanding-ELF на 0x40000000 (ABI пользовательских
 * задач; с v3 спавнится родителем через pie+TASK_SPAWN_IMAGE — загрузка по ФИКСИРОВАННЫМ
 * линк-адресам, кадры из пользовательского пула).
 *
 * Точка входа _start; сегменты: .text RX / .rodata R / .data+.bss RW.
 * -znoseparate-code: компактные смежные сегменты (меньше pow2-кадров
 * на сегмент в стейджинге родителя).
 */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

INIT_BASE = 0x40000000;

SECTIONS
{
    . = INIT_BASE;
    __init_start = .;

    .text : ALIGN(4K)
    {
        KEEP(*(.text.init))
        *(.text .text.*)
    }

    .rodata : ALIGN(4K)
    {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4K)
    {
        *(.data .data.*)
        *(.got .got.*)
    }

    .bss : ALIGN(4K)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    . = ALIGN(4K);
    __init_end = .;

    /DISCARD/ :
    {
        *(.eh_frame*)
        *(.note*)
        *(.comment*)
        *(.gcc_except_table*)
    }
}
