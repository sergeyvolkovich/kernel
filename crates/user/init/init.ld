/* ==== init.ld: пользовательский ELF init-сервера (v3) ====
 *
 * Статический freestanding-ELF на 0x60000000 (INIT_BASE протокола
 * v3; см. docs/boot-protocol-v3.md): бутстрап (flat, 0x40000000)
 * спавнит этот образ через pie+TASK_SPAWN_IMAGE по фиксированным
 * линк-адресам; архив доступен RO на ARCHIVE_BASE (0x50000000).
 *
 * Точка входа _start (userlib); сегменты: .text RX / .rodata R /
 * .data+.bss RW. -znoseparate-code: компактные смежные сегменты.
 */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

INIT_BASE = 0x60000000;

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
