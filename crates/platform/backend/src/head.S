/* ==== head.S: вход ядра из заглушки (UEFI long mode) ==== */
/* */
/* Договор с заглушкой (см. uefi_stub): */
/* * образ ядра размещён ДИНАМИЧЕСКИ: любой 2 MiB-выровненный адрес в */
/*   [16 MiB .. 4 GiB) ( physmap покрывает 4 GiB; фактическая база — */
/*   BootInfo.kernel.phys_base ); entry = смещение 0 образа; */
/* * RDI = физический адрес BootInfo v2; */
/* * прерывания заглушкой выключены; длинный режим включён; таблицы — */
/*   прошивочные (identity всей RAM): ПЕРВЫЕ инструкции идут identity. */
/* */
/* Геометрия адресов (ключ к пониманию): rip-relative lea в identity-режиме */
/* даёт ФИЗИКУ образа (адрес исполнения). Линк-адрес = физика + r12, где */
/* r12 = KERNEL_LINK_BASE - физика(_start) — вычисляется на входе, т.к. */
/* размещение динамическое. Никаких константных поправок (+2 GiB старой */
/* версии — ошибка: phys+2GiB != link; верно link = phys - 2 GiB при */
/* базе 16 MiB, и вообще link = phys + r12). */
/* */
/* Таблицы (своя сборка head.S, .bss.boot.tables): */
/* PML4[511] -> PDPT ядра [510] -> PD ядра (high-half образ, 2 MiB); */
/* PML4[256] -> PDPT physmap [0..3] -> 4 PD (физика 0..4 GiB); */
/* PML4[0]   -> тот же PDPT physmap: identity 0..4 GiB — транзит для */
/* прыжка в high-half; остаётся навсегда supervisor-only, в */
/* пользовательские таблицы не копируется (копия с PML4[256]). */
/* */
/* KERNEL_LINK_BASE = 0xFFFFFFFF81000000 (-2 GiB + 16 MiB): внутри */
/* PML4[511] смещение 510 GiB => PDPT-индекс 510; образ стартует на */
/* PD-ИНДЕКСЕ 8 (16 MiB / 2 MiB). */
/* */
/* Таблицы — .bss.boot.tables: заглушка zero-fill'ит PT_LOAD, но head.S */
/* обнуляет их сам (устойчивость к прошивкам без zero-fill). */

.intel_syntax noprefix

.set PML4_PHYSMAP_SLOT, 256
.set PML4_KERNEL_SLOT, 511
.set PML4_IDENTITY_SLOT, 0
/* KERNEL_LINK_BASE = 0xFFFFFFFF81000000: внутри PML4[511] смещение */
/* 510 GiB => индекс PDPT = 510 (запись PDPT ядра). */
.set KERNEL_PDPT_INDEX, 510

/* Одна страница PML4 служит и PDPT ядра: используемые индексы не */
/* пересекаются (PML4: 0/256/511 = смещения 0/2048/4088; PDPT: 510 = 4080). */
.set PDPT_KERNEL_OFF, 0
.set PD_KERNEL_OFF, 4096
.set PDPT_PHYSMAP_OFF, 8192
.set PD_PHYSMAP_OFF, 12288
.set TABLES_LEN, 4096 * 8   /* PDPT_k + PD_k + PDPT_pm + 4*PD_pm + резерв */

/* PD-индекс первой 2MiB-страницы образа в PD ядра: */
/* (KERNEL_LINK_BASE - база PDPT[510]) / 2MiB = 16MiB / 2MiB = 8. */
.set PD_KERNEL_FIRST, 8

.set PTE_P, 1
.set PTE_RW, 2
.set PTE_PS, 128            /* 2 MiB-страница (запись уровня PD) */

/* Линк-адрес ядра (совпадает с kernel.ld и arch_x86::boot). */
.set KERNEL_LINK_BASE, 0xFFFFFFFF81000000
.set PAGE2M, 0x200000

.section .text.boot, "ax"
.code64
.globl _start
_start:
    cli
    /* RDI = BootInfo phys — сохраняем в callee-saved до kmain. */
    mov r15, rdi

    /* r12 = LINK - PHYS образа (динамическое размещение): физика _start */
    /* = база образа (entry по смещению 0; заглушка выравнивает на 2 MiB). */
    lea rax, [rip + _start]
    mov rcx, KERNEL_LINK_BASE
    sub rcx, rax
    mov r12, rcx

    /* ── 0. Обнулить страницы таблиц (lea = физика: identity-режим). */
    lea rax, [rip + __boot_tables]
    lea rcx, [rip + __boot_tables_end]
1:  cmp rax, rcx
    jae 2f
    mov qword ptr [rax], 0
    add rax, 8
    jmp 1b
2:

    /* ── 1. PML4-записи (физика таблиц = lea, без поправок). */
    lea rax, [rip + __boot_tables]

    /* PML4[511] -> PDPT ядра. */
    lea rcx, [rip + __boot_tables + PDPT_KERNEL_OFF]
    or rcx, (PTE_P | PTE_RW)
    mov [rax + PML4_KERNEL_SLOT*8], rcx

    /* PML4[256] -> PDPT physmap. */
    lea rcx, [rip + __boot_tables + PDPT_PHYSMAP_OFF]
    or rcx, (PTE_P | PTE_RW)
    mov [rax + PML4_PHYSMAP_SLOT*8], rcx

    /* PML4[0] -> тот же PDPT physmap: identity 0..4 GiB (транзит). */
    mov [rax + PML4_IDENTITY_SLOT*8], rcx

    /* ── 2. Ядро high-half: PDPT[510] -> PD ядра; PD[i] = образ 2MiB-кадры. */
    lea rax, [rip + __boot_tables + PDPT_KERNEL_OFF]
    lea rcx, [rip + __boot_tables + PD_KERNEL_OFF]
    or rcx, (PTE_P | PTE_RW)
    mov [rax + KERNEL_PDPT_INDEX*8], rcx

    /* Число 2MiB-записей = ceil(длина образа / 2 MiB); длина — из */
    /* линк-символов (runtime lea-разность, без чтения памяти). */
    lea rsi, [rip + __kernel_start]
    lea rdi, [rip + __kernel_end]
    sub rdi, rsi
    add rdi, PAGE2M - 1
    shr rdi, 21          /* rdi = n (страниц образа) */

    lea rax, [rip + __boot_tables + PD_KERNEL_OFF]
    lea rcx, [rip + _start]        /* физика 1-й страницы образа */
    mov rdx, PD_KERNEL_FIRST       /* стартовый PD-индекс образа */
    mov r8, rdx
    add r8, rdi                    /* конец (эксклюзивно) */
3:  cmp rdx, r8
    jae 4f
    mov r9, rcx
    or r9, (PTE_P | PTE_RW | PTE_PS)
    mov [rax + rdx*8], r9
    add rcx, PAGE2M
    inc rdx
    jmp 3b
4:

    /* ── 3. Physmap: PDPT_pm[0..3] -> 4 PD (контуры в памяти подряд). */
    lea rax, [rip + __boot_tables + PDPT_PHYSMAP_OFF]
    xor rdx, rdx
    lea r9, [rip + __boot_tables + PD_PHYSMAP_OFF]
5:  cmp rdx, 4
    jae 6f
    mov rcx, r9
    or rcx, (PTE_P | PTE_RW)
    mov [rax + rdx*8], rcx
    add r9, 4096
    inc rdx
    jmp 5b
6:
    /* 4 PD подряд: 2048 × 2MiB = физика 0..4 GiB. */
    lea rax, [rip + __boot_tables + PD_PHYSMAP_OFF]
    xor r10, r10
    mov r11, 2048
7:  cmp r10, r11
    jae 8f
    mov rcx, r10
    shl rcx, 21
    or rcx, (PTE_P | PTE_RW | PTE_PS)
    mov [rax + r10*8], rcx
    inc r10
    jmp 7b
8:

    /* ── 4. Новые таблицы; identity живёт (PML4[0]), прыжок high-half. */
    lea rax, [rip + __boot_tables]
    mov cr3, rax

    lea rax, [rip + high_entry]
    add rax, r12          /* phys + (link-phys) = линк-адрес */
    jmp rax

high_entry:
    /* Исполняемся по линк-адресам (high-half); R15 = BootInfo phys. */
    lea rsp, [rip + __boot_stack_top]
    mov rdi, r15
    xor rbp, rbp
    call kmain                    /* не возвращается */
    cli
9:  hlt
    jmp 9b

/* ── Данные ── */
.section .bss.boot.tables, "aw", @nobits
.align 4096
.globl __boot_tables
__boot_tables:
    .zero TABLES_LEN
.globl __boot_tables_end
__boot_tables_end:

/* Стек kmain (64 KiB). */
.section .bss.boot.stack, "aw", @nobits
.align 16
.globl __boot_stack_bottom
__boot_stack_bottom:
    .zero 65536
.globl __boot_stack_top
__boot_stack_top:
