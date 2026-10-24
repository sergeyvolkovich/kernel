/* ==== bootstrap.ld: FLAT-образ бутстрапа (протокол загрузки v3) ====
 *
 * Статический freestanding-ELF на 0x40000000 (FLAT_BASE ABI v3;
 * см. startup::flatload — загрузка по фиксированным линк-адресам,
 * кадры из пользовательского пула; mkarchive.py переводит образ
 * в FLAT-формат и вкладывает в заголовок RLBA).
 *
 * Точка входа _start (userlib); сегменты: .text RX / .rodata R /
 * .data+.bss RW. -znoseparate-code: компактные смежные сегменты.
 */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

BOOTSTRAP_BASE = 0x40000000;

SECTIONS
{
    . = BOOTSTRAP_BASE;
    __bootstrap_start = .;

    .text : ALIGN(4K)
    {
        KEEP(*(.text.bootstrap))
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
    __bootstrap_end = .;

    /DISCARD/ :
    {
        *(.eh_frame*)
        *(.note*)
        *(.comment*)
        *(.gcc_except_table*)
    }
}
