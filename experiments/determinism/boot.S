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
    movb %dl, boot_drive

    movb $0x02, %ah
    movb $0x01, %al
    xorw %cx, %cx
    movb $0x02, %cl
    xorb %dh, %dh
    movb boot_drive, %dl
    movw $0x8000, %bx
    int $0x13
    jc disk_error

    xorw %ax, %ax
    movw %ax, %ds
    movw $0x8000, %si
    call print
    xorb %al, %al
    jmp exit

disk_error:
    xorw %ax, %ax
    movw %ax, %ds
    movw $disk_error_message, %si
    call print
    movb $0x02, %al

exit:
    movw $0x00f4, %dx
    outb %al, %dx
halt:
    cli
    hlt
    jmp halt

print:
    lodsb
    testb %al, %al
    jz print_done
    outb %al, $0xe9
    jmp print
print_done:
    ret

boot_drive:
    .byte 0
disk_error_message:
    .asciz "vf-disk-error\n"

.org 510
.word 0xaa55
.org 512
.asciz "vf-disk-ok\n"
.org 1024, 0
