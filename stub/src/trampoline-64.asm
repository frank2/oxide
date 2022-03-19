[BITS 64]
   
   global _start

_start:
   ;; == args ==
   ;; r12: target_base
   ;; r13: current_base
   ;; r14: size
   ;; r15: entrypoint
   ;; rbp+0x30: VirtualProtect
   ;; rbp+0x38: VirtualQuery
   ;; rbp+0x40: GetCommandLineA
   ;; rbp+0x48: AddVectoredExceptionHandler
   ;; rbp+0x50: RemoveVectoredExceptionHandler

   ;; size of MEMORY_BASIC_INFORMATION: 0x30
   
   ;; == stack ==
   ;; rbp-0x8: base address of this buffer
   ;; rbp-0x38: MEMORY_BASIC_INFORMATION
   ;; rbp-0x40: old protect
   ;; rbp-0x48: write offset
   ;; rbp-0x50: VEH handle (_RTL_VECTORED_EXCEPTION_ENTRY)
   ;; rbp-0x58: TLS callback array

   ;; == MEMORY__BASIC_INFORMATION ==
   ;; rbp-0x38: BaseAddress
   ;; rbp-0x30: AllocationBase
   ;; rbp-0x28: AllocationProtect
   ;; rbp-0x24: padding
   ;; rbp-0x20: RegionSize
   ;; rbp-0x18: State
   ;; rbp-0x14: Protect
   ;; rbp-0x10: Type
   ;; rbp-0xC: padding

   ;; == _RTL_VECTORED_EXCEPTION_ENTRY ==
   ;; base+0x0: LIST_ENTRY.Flink
   ;; base+0x8: LIST_ENTRY.Blink
   ;; base+0x10: Flag
   ;; base+0x14: RefCount
   ;; base+0x18: VectoredHandler

   call popper
popper:
   pop rax
   sub rax,9
   
   push rbp
   mov rbp,rsp
   sub rsp,0x60

   push rbx
   push r12
   push r13
   push r14
   push r15
   push rsi
   push rdi

   mov r12, rcx
   mov r13, rdx
   mov r14, r8
   mov r15, r9

   mov [rbp-0x8], rax
   
   ;; zero out the MEMORY_BASIC_INFORMATION structure
   lea rdi, [rbp-0x38]
   mov rcx, 0x30
   xor rax, rax
   repnz stosb

   mov qword [rbp-0x40], 0
   mov qword [rbp-0x48], 0
   mov qword [rbp-0x50], 0
   mov qword [rbp-0x58], 0

;;; check for a TLS directory
   mov eax, dword [r12+0x3C]   ; target_base / e_lfanew
   add rax, r12                  ; IMAGE_NT_HEADERS32
   mov eax, dword [rax+0xD0]   ; IMAGE_NT_HEADERS32.OptionalHeader.DataDirectories[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress
   
   test rax, rax
   jz no_tls_section

;;; we have a TLS directory, get the address of the callbacks
   add rax, r12                 ; IMAGE_TLS_DIRECTORY64
   mov rsi, [rax+0x18]          ; IMAGE_TLS_DIRECTORY64.AddressOfCallbacks
   mov qword [rbp-0x58], rsi    ; store the callback array for later

patch_tls_callbacks:
   lodsq                        ; load the callback into rax
   test rax,rax
   jz end_patching              ; callback array ends on NULL

	mov rdi, rax
   lea r9, [rbp-0x40]           ; lpflOldProtect
   mov r8, 0x40                 ; PAGE_EXECUTE_READWRITE
   mov rdx, 1                   ; patch size
   mov rcx, rdi                 ; patch address
   call [rbp+0x30]              ; VirtualProtect
   
   mov byte [rdi], 0x90         ; patch function with cld

   lea r9, [rbp-0x40]           ; lpflOldProtect
   mov r8, [r9]                 ; old protect value
   mov rdx, 1                   ; patch size
   mov rcx, rdi                 ; patch address
   call [rbp+0x30]              ; VirtualProtect

   jmp patch_tls_callbacks
   
end_patching:
   ;; wipe out the root TLS allocation

   ;; TLS structure:
   ;; base+0x0: qword
   ;; base+0x8: qword
   ;; base+0x10: qword
   ;; base+0x18: qword
   ;; base+0x20: qword
   ;; base+0x28: dword, boolean
   ;; base+0x2c: dword,
   ;; base+0x30: qword
   ;; base+0x38: qword ptr, thread information structure
   ;; base+0x40: dword, boolean
   ;; base+0x44: dword
   ;; base+0x48: qword
   ;; base+0x50: qword
   ;; base+0x58: qword
   ;; base+0x60: qword
   mov rax, [gs:0x58]
   mov rdi, [rax]                ; TLS index 0
   mov rcx, 0x68
   xor rax, rax
   repne stosb
   
no_tls_section:   
   mov rbx, r12                  ; target base
   mov rdi, rbx
   add rdi, r14                  ; size

memory_search:
   cmp rbx, rdi
   jge search_complete

   mov r8, 0x30                 ; MEMORY_BASIC_INFORMATION structure size
   
   lea rdx, [rbp-0x38]          ; MEMORY_BASIC_INFORMATION structure

   mov rcx, rbx                 ; address
   call [rbp+0x38]              ; VirtualQuery

   cmp rax, 0x30
   jnz search_complete

   lea r9, [rbp-0x40]           ; lpflOldProtect
   mov r8, 0x40                 ; PAGE_EXECUTE_READWRITE
   mov rdx, [rbp-0x20]          ; MEMORY_BASIC_INFORMATION.RegionSize
   mov rcx, [rbp-0x38]          ; MEMORY_BASIC_INFORMATION.BaseAddress
   call [rbp+0x30]              ; VirtualProtect

   test rax,rax
   jz error

   mov rsi, r13                 ; current base
   add rsi, [rbp-0x48]          ; write offset

   push rdi
   mov rdi, [rbp-0x38]          ; MEMORY_BASIC_INFORMATION.BaseAddress

   mov rcx, r14                 ; size
   sub rcx, [rbp-0x48]          ; write offset / calculates the size left to write
	
   mov rax, [rbp-0x20]          ; MEMORY_BASIC_INFORMATION.RegionSize

   cmp rcx, rax                 ; compare the data left to the queried buffer's region size
   jle use_data_left
	
   mov rcx, rax

use_data_left:
   mov rax, rcx
   repnz movsb

   pop rdi

   add qword [rbp-0x48], rax    ; write offset
   add rbx, [rbp-0x20]          ; MEMORY_BASIC_INFORMATION.RegionSize
   jmp memory_search

search_complete:
   mov rdx, [rbp-0x8]           ; base address of current buffer
   add rdx, _veh                ; our dummy VEH
   mov rcx, 1                   ; call this handler first
   call [rbp+0x48]              ; AddVectoredExceptionHandler

   mov rsi, rax                 ; _RTL_VECTORED_EXCEPTION_ENTRY
 
   mov rcx, [rax]               ; LIST_ENTRY.Flink / Rust VEH handler
   call [rbp+0x50]              ; RemoveVectoredExceptionHandler
   
   mov rcx, rsi                 ; the handler we registered
   call [rbp+0x50]              ; RemoveVectoredExceptionHandler

;;; call our TLS callbacks
   mov rsi, [rbp-0x58]          ; get TLS callback array
	
   test rsi,rsi
   jz finish_calling_callbacks
   
   cld

call_callbacks:
   lodsq                        ; load the callback into eax
   test rax,rax
   jz finish_calling_callbacks
   
   xor r8,r8                    ; PVOID Reserved
   mov rdx, 1                   ; DWORD Reason / DLL_PROCESS_ATTACH
   mov rcx, r12                 ; PVOID DllHandle
   call rax                     ; call TLS callback
   jmp call_callbacks

finish_calling_callbacks:  
   xor r9, r9                   ; cmdShow
	
   call [rbp+0x40]              ; GetCommandLineA
   mov r8, rax                  ; cmdLine
   
   xor rdx, rdx                 ; prevInstance

   mov rcx, r12                 ; target base / instance

   mov rbx, rcx
   add rbx, r15                 ; new entrypoint
   add rsp, 0x88                ; stack rewind + 0x20 shadow space
   mov qword [rsp], 0           ; zero out the shadow space
   mov qword [rsp+0x8], 0
   mov qword [rsp+0x10], 0
   mov qword [rsp+0x18], 0
   call rbx                     ; call entrypoint

error:  
   pop rdi
   pop rsi
   pop r15
   pop r14
   pop r13
   pop r12
   pop rbx
   
   add rsp,0x60
   pop rbp
   ret 0x28

_veh:
   mov rax,0xFFFFFFFF
   ret 8
