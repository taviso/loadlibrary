;; x64 Windows <=> Linux x86_64 calling convention switcher.
;; Author: Alessandro De Vito (cube0x8)

extern malloc
extern free

SECTION .bss
    temp_buffer: resq 0x6
    ptr_array: resq 0xc8

SECTION .data
    index:   dd  0x0

SECTION .text
    GLOBAL x86_64_call_exported_function
    GLOBAL nix_to_win
    GLOBAL win_to_nix
    GLOBAL win_to_nix_5
    GLOBAL win_to_nix_6

x86_64_call_exported_function:
    mov rax, rdi
    mov rdi, rsi
    mov rsi, rdx
    mov rdx, rcx
    mov rcx, r8
    mov r8, r9
    mov r9, [rsp+0x8]
    jmp nix_to_win

nix_to_win:
    ;; pusha
    push rdi
    push rsi
    push rdx
    push rcx
    push rbx
    push rax
    push r8
    push r9
    ;; allocate 16 bytes on the heap
    mov rdi, 0x10
    call malloc WRT ..plt
    ;; get the original return address from the stack
    mov r11, [rsp+0x40]
    ;; store it on the heap
    mov [rax], r11
    ;; store rbx (preserved register)
    mov rbx, QWORD[rsp+0x18]
    mov [rax+0x8], rbx
    ;; store the pointer to the heap block in the global array
    lea rbx, [rel ptr_array]
    mov ecx, [rel index]
    imul edi, ecx, 0x8
    mov [rbx+rdi], rax
    inc ecx
    mov DWORD[rel index], ecx

    ;; restore registers
    pop r9
    pop r8
    pop rax
    pop rbx
    pop rcx
    pop rdx
    pop rsi
    pop rdi

    ;; skip the original return address
    add rsp, 0x8

    ;; calling convetion switch
    push r9
    push r8
    ;; slack space
    sub rsp, 0x20

    mov r9,  rcx
    mov r8,  rdx
    mov rdx, rsi
    mov rcx, rdi

    ;; call the target function
    call rax
    ;; store the result in the temporary buffer
    lea rbx, [rel temp_buffer]
    mov [rbx], rax
    ;; reset the stack to its original form (slack space - r9 -r8)
    add rsp, 0x30

    ;; take the array_ptr index and decrement it
    mov ecx, [rel index]
    dec ecx
    mov DWORD[rel index], ecx
    ;; take our heap block address
    lea rbx, [rel ptr_array]
    imul edi, ecx, 0x8
    mov r11, QWORD [rbx+rdi]
    ;; get the old original return address and store it in the temporary buffer
    mov rcx, QWORD [r11]
    lea rbx, [rel temp_buffer]
    mov [rbx+0x8], rcx
    ;; get the old rbx value and store it in the temporary buffer
    mov rax, QWORD [r11+0x8]
    mov [rbx+0x10], rax
    ;; free the heap block
    mov rdi, r11
    call free WRT ..plt

    ;; restore the result
    lea r11, [rel temp_buffer]
    mov rax, QWORD[r11]
    ;; restore rbx
    mov rbx, [r11+0x10]
    ;; restore the original return address
    mov rcx, [r11+0x8]
    push rcx
    ret

win_to_nix:
    ;; pusha
    push rdi
    push rsi
    push rdx
    push rcx
    push rbx
    push rax
    push r8
    push r9
    push rbp
    ;; allocate 56 bytes on the heap
    mov rdi, 0x38
    call malloc WRT ..plt
    ;; get the original return address from the stack
    mov r11, [rsp+0x48]
    ;; store it on the heap
    mov [rax], r11
    ;; store the pointer to the heap block in the global array
    lea rbx, [rel ptr_array]
    mov ecx, [rel index]
    imul edi, ecx, 0x8
    mov [rbx+rdi], rax
    inc ecx
    mov DWORD[rel index], ecx

    ;; store rdi, rsi, rbx and rbp (preserved registers on windows x64)
    mov rdi, QWORD [rsp+0x40]
    mov [rax+0x8], rdi
    mov rsi, QWORD [rsp+0x38]
    mov [rax+0x10], rsi
    mov rbx, QWORD [rsp+0x20]
    mov [rax+0x18], rbx
    mov rbx, QWORD [rsp]
    mov [rax+0x20], rbx

    ;; restore registers
    pop rbp
    pop r9
    pop r8
    pop rax
    pop rbx
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    ;; skip the original return address
    add rsp, 0x8

    mov rdi, rcx
    mov rsi, rdx
    mov rdx, r8
    mov rcx, r9

    ;; skip slack space
    add rsp, 0x20

    call rax
    ;; store the result in the temporary buffer
    lea rbx, [rel temp_buffer]
    mov [rbx], rax
    ;; reset the stack to its original form (slack space)
    sub rsp, 0x20

    ;; take the array_ptr index and decrement it
    mov ecx, [rel index]
    dec ecx
    mov DWORD[rel index], ecx
    ;; take our heap block address
    lea rbx, [rel ptr_array]
    imul edi, ecx, 0x8
    mov r11, QWORD [rbx+rdi]

    ;; get the old original return address and store it in the temporary buffer
    mov rcx, [r11]
    lea rbx, [rel temp_buffer]
    mov [rbx+0x8], rcx
    ;; restore callee preserved registers

    ;; rdi
    mov rax, QWORD [r11+0x8]
    mov [rbx+0x10], rax
    ;; rsi
    mov rax, QWORD [r11+0x10]
    mov [rbx+0x18], rax
    ;; rbx
    mov rax, QWORD [r11+0x18]
    mov [rbx+0x20], rax
    ;; rbp
    mov rax, QWORD [r11+0x20]
    mov [rbx+0x28], rax

    ;; free the heap block
    mov rdi, r11
    call free WRT ..plt

    ;; restore the result
    lea r11, [rel temp_buffer]
    mov rax, QWORD[r11]
    ;; restore the original return address
    mov rcx, [r11+0x8]
    ;; restore rdi
    mov rdi, QWORD[r11+0x10]
    ;; restore rsi
    mov rsi, QWORD[r11+0x18]
    ;; restore rbx
    mov rbx, QWORD[r11+0x20]
    ;; restore rbp
    mov rbp, QWORD[r11+0x28]

    ;; push the original return address
    push rcx
    ret

win_to_nix_5:
    ;; pusha
    push rdi
    push rsi
    push rdx
    push rcx
    push rbx
    push rax
    push r8
    push r9
    push rbp
    ;; allocate 56 bytes on the heap
    mov rdi, 0x38
    call malloc WRT ..plt
    ;; get the original return address from the stack
    mov r11, [rsp+0x48]
    ;; store it on the heap
    mov [rax], r11
    ;; store the pointer to the heap block in the global array
    lea rbx, [rel ptr_array]
    mov ecx, [rel index]
    imul edi, ecx, 0x8
    mov [rbx+rdi], rax
    inc ecx
    mov DWORD[rel index], ecx

    ;; store rdi, rsi, rbx and rbp (preserved registers on windows x64)
    mov rdi, QWORD [rsp+0x40]
    mov [rax+0x8], rdi
    mov rsi, QWORD [rsp+0x38]
    mov [rax+0x10], rsi
    mov rbx, QWORD [rsp+0x20]
    mov [rax+0x18], rbx
    mov rbp, QWORD [rsp]
    mov [rax+0x20], rbp
    ;; preserve arg5
    mov rbx, QWORD [rsp+0x70]
    mov [rax+0x28], rbx

    ;; restore registers
    pop rbp
    pop r9
    pop r8
    pop rax
    pop rbx
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    ;; skip the original return address
    add rsp, 0x8

    mov rdi, rcx
    mov rsi, rdx
    mov rdx, r8
    mov rcx, r9
    mov r8, QWORD [rsp+0x20]

    ;; skip slack space + 5th arg: (0x20) = 0x30
    add rsp, 0x28

    call rax
    ;; store the result in the temporary buffer
    lea rbx, [rel temp_buffer]
    mov [rbx], rax
    ;; reset the stack to its original form (slack space + r8)
    sub rsp, 0x28

    ;; take the array_ptr index and decrement it
    mov ecx, [rel index]
    dec ecx
    mov DWORD[rel index], ecx
    ;; take our heap block address
    lea rbx, [rel ptr_array]
    imul edi, ecx, 0x8
    mov r11, QWORD [rbx+rdi]

    ;; get the old original return address and store it in the temporary buffer
    mov rcx, [r11]
    lea rbx, [rel temp_buffer]
    mov [rbx+0x8], rcx
    ;; restore callee preserved registers

    ;; rdi
    mov rax, QWORD [r11+0x8]
    mov [rbx+0x10], rax
    ;; rsi
    mov rax, QWORD [r11+0x10]
    mov [rbx+0x18], rax
    ;; rbx
    mov rax, QWORD [r11+0x18]
    mov [rbx+0x20], rax
    ;; rbp
    mov rax, QWORD [r11+0x20]
    mov [rbx+0x28], rax

    ;; restore arg5
    mov rax, QWORD[r11+0x28]
    mov [rsp+0x20], rax

    ;; free the heap block
    mov rdi, r11
    call free WRT ..plt

    ;; restore the result
    lea r11, [rel temp_buffer]
    mov rax, QWORD[r11]
    ;; restore the original return address
    mov rcx, [r11+0x8]
    ;; restore rdi
    mov rdi, QWORD[r11+0x10]
    ;; restore rsi
    mov rsi, QWORD[r11+0x18]
    ;; restore rbx
    mov rbx, QWORD[r11+0x20]
    ;; restore rbp
    mov rbp, QWORD[r11+0x28]

    ;; push the original return address
    push rcx
    ret

win_to_nix_6:
    ;; pusha
    push rdi
    push rsi
    push rdx
    push rcx
    push rbx
    push rax
    push r8
    push r9
    push rbp
    ;; allocate 56 bytes on the heap
    mov rdi, 0x38
    call malloc WRT ..plt
    ;; get the original return address from the stack
    mov r11, [rsp+0x48]
    ;; store it on the heap
    mov [rax], r11
    ;; store the pointer to the heap block in the global array
    lea rbx, [rel ptr_array]
    mov ecx, [rel index]
    imul edi, ecx, 0x8
    mov [rbx+rdi], rax
    inc ecx
    mov DWORD[rel index], ecx

    ;; store rdi, rsi, rbx and rbp (preserved registers on windows x64)
    mov rdi, QWORD [rsp+0x40]
    mov [rax+0x8], rdi
    mov rsi, QWORD [rsp+0x38]
    mov [rax+0x10], rsi
    mov rbx, QWORD [rsp+0x20]
    mov [rax+0x18], rbx
    mov rbp, QWORD [rsp]
    mov [rax+0x20], rbp
    ;; preserve arg5 and arg6
    mov rbx, QWORD [rsp+0x70]
    mov [rax+0x28], rbx
    mov rbx, QWORD [rsp+0x78]
    mov [rax+0x30], rbx

    ;; restore registers
    pop rbp
    pop r9
    pop r8
    pop rax
    pop rbx
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    ;; skip the original return address
    add rsp, 0x8

    mov rdi, rcx
    mov rsi, rdx
    mov rdx, r8
    mov rcx, r9
    mov r8, QWORD [rsp+0x20]
    mov r9, QWORD [rsp+0x28]

    ;; skip slack space + 5th and 6th args: (0x20) + arg5 (0x8) + arg6 (0x8) = 0x30
    add rsp, 0x30

    call rax
    ;; store the result in the temporary buffer
    lea rbx, [rel temp_buffer]
    mov [rbx], rax
    ;; reset the stack to its original form (slack space + r9 + r8)
    sub rsp, 0x30

    ;; take the array_ptr index and decrement it
    mov ecx, [rel index]
    dec ecx
    mov DWORD[rel index], ecx
    ;; take our heap block address
    lea rbx, [rel ptr_array]
    imul edi, ecx, 0x8
    mov r11, QWORD [rbx+rdi]

    ;; get the old original return address and store it in the temporary buffer
    mov rcx, [r11]
    lea rbx, [rel temp_buffer]
    mov [rbx+0x8], rcx
    ;; restore callee preserved registers

    ;; rdi
    mov rax, QWORD [r11+0x8]
    mov [rbx+0x10], rax
    ;; rsi
    mov rax, QWORD [r11+0x10]
    mov [rbx+0x18], rax
    ;; rbx
    mov rax, QWORD [r11+0x18]
    mov [rbx+0x20], rax
    ;; rbp
    mov rax, QWORD [r11+0x20]
    mov [rbx+0x28], rax

    ;; restore arg5 and arg6 on the stack
    mov rax, QWORD[r11+0x28]
    mov [rsp+0x20], rax
    mov rax, QWORD[r11+0x30]
    mov [rsp+0x28], rax

    ;; free the heap block
    mov rdi, r11
    call free WRT ..plt

    ;; restore the result
    lea r11, [rel temp_buffer]
    mov rax, QWORD[r11]
    ;; restore the original return address
    mov rcx, [r11+0x8]
    ;; restore rdi
    mov rdi, QWORD[r11+0x10]
    ;; restore rsi
    mov rsi, QWORD[r11+0x18]
    ;; restore rbx
    mov rbx, QWORD[r11+0x20]
    ;; restore rbp
    mov rbp, QWORD[r11+0x28]

    ;; push the original return address
    push rcx
    ret