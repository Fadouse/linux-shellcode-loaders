.global _start

.section .text
_start:
    mov $1, %rax                    /* sys_write */
    mov $1, %rdi                    /* stdout */
    lea message(%rip), %rsi
    mov $message_len, %rdx
    syscall

    mov $60, %rax                   /* sys_exit */
    xor %rdi, %rdi
    syscall

.section .rodata
message:
    .ascii "helloworld from manual ELF loader shellcode-style ELF!\n"
.set message_len, . - message
