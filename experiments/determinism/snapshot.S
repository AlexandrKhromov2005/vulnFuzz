.section .text
.code16
.global _start
_start:
    cli
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw $0x7c00, %sp
    movb %dl, (0x7c00 + boot_drive)

    call read_sector
    jc disk_error

    movw $(0x7c00 + stage2_message), %si
    movw $0x8000, %di
    movw $(stage2_message_end - stage2_message), %cx
    rep movsb
    movb $0x03, %ah
    movb $0x01, %al
    movb $0x02, %cl
    movb (0x7c00 + boot_drive), %dl
    int $0x13
    pushf
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    popf
    jc disk_error

    movw $(0x7c00 + stage1_message), %si
    call print
    call wait_for_interrupts
    call read_sector
    jc disk_error
    movw $0x8000, %si
    call print
    call wait_for_interrupts

halt:
    cli
    hlt
    jmp halt

read_sector:
    xorw %ax, %ax
    movw %ax, %es
    movb $0x02, %ah
    movb $0x01, %al
    xorw %cx, %cx
    movb $0x02, %cl
    xorb %dh, %dh
    movb (0x7c00 + boot_drive), %dl
    movw $0x8000, %bx
    int $0x13
    pushf
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    popf
    ret

wait_for_interrupts:
    movw $0x0040, %cx
wait_tick:
    sti
    hlt
    cli
    loop wait_tick
    ret

print:
    lodsb
    testb %al, %al
    jz print_done
    outb %al, $0xe9
    jmp print
print_done:
    ret

disk_error:
    movw $(0x7c00 + disk_error_message), %si
    call print
    jmp halt

boot_drive:
    .byte 0
disk_error_message:
    .asciz "vf-snapshot-disk-error\n"
stage1_message:
    .asciz "vf-stage-1\n"
stage2_message:
    .asciz "vf-stage-2\n"
stage2_message_end:

.org 510
.word 0xaa55
.org 512
.asciz "vf-stage-1\n"
.org 1024, 0
