/* ==== init.ld: пользовательский ELF init-сервера ====
 *
 * Статический freestanding-ELF на 0x40000000 (ABI пользовательских
 * задач v0.5; см. startup::elfload — загрузка по ФИКСИРОВАННЫМ
 * линк-адресам, кадры из пользовательского пула).
 *
 * Точка входа _start (userlib); сегменты: .text RX / .rodata R /
 * .data+.bss RW. -znoseparate-code: компактные смежные сегменты
 * (меньше pow2-кадров на сегмент в elfload::user_frames).
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
