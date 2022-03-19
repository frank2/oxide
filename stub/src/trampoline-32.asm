[BITS 32]
   
   global _start

_start:
   ;; == args ==
   ;; ebp+0x8: target_base
   ;; ebp+0xC: current_base
   ;; ebp+0x10: size
   ;; ebp+0x14: entrypoint
   ;; ebp+0x18: VirtualProtect
   ;; ebp+0x1C: VirtualQuery
   ;; ebp+0x20: GetCommandLineA
   ;; ebp+0x24: AddVectoredExceptionHandler
   ;; ebp+0x28: RemoveVectoredExceptionHandler
   ;; ebp+0x2c: TlsFree

   ;; size of MEMORY_BASIC_INFORMATION: 0x1C
   
   ;; == stack ==
   ;; ebp-0x4: base address of this buffer
   ;; ebp-0x20: MEMORY_BASIC_INFORMATION
   ;; ebp-0x24: old protect
   ;; ebp-0x28: write offset
   ;; ebp-0x2c: VEH handle (_RTL_VECTORED_EXCEPTION_ENTRY)
   ;; ebp-0x30: TLS callback array

   ;; == MEMORY__BASIC_INFORMATION ==
   ;; ebp-0x20: BaseAddress
   ;; ebp-0x1c: AllocationBase
   ;; ebp-0x18: AllocationProtect
   ;; ebp-0x14: RegionSize
   ;; ebp-0x10: State
   ;; ebp-0xC: Protect
   ;; ebp-0x8: Type

   ;; == _RTL_VECTORED_EXCEPTION_ENTRY ==
   ;; base+0x0: LIST_ENTRY.Flink
   ;; base+0x4: LIST_ENTRY.Blink
   ;; base+0x8: Flag
   ;; base+0xC: RefCount
   ;; base+0x10: VectoredHandler

   call popper
popper:
   pop eax
   sub eax,5
   
   push ebp
   mov ebp,esp
   sub esp,0x34

   push ebx
   push esi
   push edi

   mov [ebp-0x4], eax
 
   ;; zero out the MEMORY_BASIC_INFORMATION structure
   lea edi, [ebp-0x20]
   mov ecx, 0x1c
   xor eax,eax
   repnz stosb

   mov dword [ebp-0x24], 0
   mov dword [ebp-0x28], 0
   mov dword [ebp-0x2c], 0
   mov dword [ebp-0x30], 0

;;; check for a TLS directory
   mov ebx, [ebp+0x8]           ; target base
   mov eax, [ebx+0x3C]          ; e_lfanew
   add eax, ebx                 ; IMAGE_NT_HEADERS32
   mov eax, [eax+0xC0]          ; IMAGE_NT_HEADERS32.OptionalHeader.DataDirectories[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress
   
   test eax, eax
   jz no_tls_section

;;; we have a TLS directory, free the current TLS index and get the address of the callbacks
   add eax, ebx                 ; IMAGE_TLS_DIRECTORY64
   mov esi, [eax+0xC]           ; IMAGE_TLS_DIRECTORY64.AddressOfCallbacks
   mov dword [ebp-0x30], esi    ; store the callback array for later

patch_tls_callbacks:
   lodsd                        ; load the callback into eax
   test eax,eax
   jz end_patching              ; callback array ends on NULL

	mov edi, eax
   lea eax, [ebp-0x24]          ; lpflOldProtect
   push eax
   push 0x40                    ; PAGE_EXECUTE_READWRITE
   push 2                       ; patch size
   push edi                     ; patch address
   call [ebp+0x18]              ; VirtualProtect
   
   mov word [edi], 0xEB         ; patch function with jmp+$0

   lea eax, [ebp-0x24]          ; lpflOldProtect
   push eax
   push dword [eax]
   push 1
   push edi
   call [ebp+0x18]              ; VirtualProtect

   jmp patch_tls_callbacks
	
end_patching:
   ;; in 32-bit there's no root allocation to mangle, so there's nothing to be done TLS-wise
   
no_tls_section:   
;;; copy over the new PE data
   mov ebx, [ebp+0x8]           ; target base
   mov edi, ebx
   add edi, [ebp+0x10]          ; size

memory_search:
   cmp ebx, edi
   jge search_complete

   push 0x1c                    ; MEMORY_BASIC_INFORMATION structure size
   
   lea eax, [ebp-0x20]          ; MEMORY_BASIC_INFORMATION structure
   push eax

   push ebx                     ; address
   call [ebp+0x1C]              ; VirtualQuery

   cmp eax, 0x1c
   jnz search_complete

   lea eax, [ebp-0x24]          ; lpflOldProtect
   push eax                     
   push 0x40                    ; PAGE_EXECUTE_READWRITE
   push dword [ebp-0x14]        ; MEMORY_BASIC_INFORMATION.RegionSize
   push dword [ebp-0x20]        ; MEMORY_BASIC_INFORMATION.BaseAddress
   call [ebp+0x18]              ; VirtualProtect

   test eax,eax
   jz error

   mov esi, [ebp+0xC]           ; current base
   add esi, [ebp-0x28]          ; write offset

   push edi
   mov edi, [ebp-0x20]          ; MEMORY_BASIC_INFORMATION.BaseAddress

   mov ecx, [ebp+0x10]          ; size
   sub ecx, [ebp-0x28]          ; calculate data left
   mov eax, [ebp-0x14]          ; MEMORY_BASIC_INFORMATION.RegionSize

   cmp ecx, eax
   jle use_data_left
	
   mov ecx, eax

use_data_left:
   mov eax, ecx
   repnz movsb

   pop edi

   add dword [ebp-0x28], eax    ; write offset
   add ebx, [ebp-0x14]          ; MEMORY_BASIC_INFORMATION.RegionSize
   jmp memory_search

search_complete:
;;; remove the Rust vectored exception handler
   mov eax, [ebp-0x4]           ; base address of current buffer
   add eax, _veh                ; our dummy VEH
   push eax                     ; VEH handler
   push 1                       ; call this handler first
   call [ebp+0x24]              ; AddVectoredExceptionHandler

   mov esi, eax                 ; _RTL_VECTORED_EXCEPTION_ENTRY
 
   mov edi, [eax]               ; LIST_ENTRY.Flink
   push edi                     ; Rust VEH handler
   call [ebp+0x28]              ; RemoveVectoredExceptionHandler
   
   push esi                     ; the handler we registered
   call [ebp+0x28]              ; RemoveVectoredExceptionHandler

;;; call our TLS callbacks
   mov ebx, [ebp+0x8]           ; target base
   mov esi, [ebp-0x30]          ; get TLS callback array

   test esi,esi
   jz finish_calling_callbacks
   
call_callbacks:
   lodsd                        ; load the callback into eax
   test eax,eax
   jz finish_calling_callbacks
   
   push 0                       ; PVOID Reserved
   push 1                       ; DWORD Reason / DLL_PROCESS_ATTACH
   push ebx                     ; PVOID DllHandle
   call eax                     ; call TLS callback
   jmp call_callbacks

finish_calling_callbacks:  
   push 0                       ; cmdShow
   
   call [ebp+0x20]              ; GetCommandLineA
   push eax                     ; cmdLine
   
   push 0                       ; prevInstance

   push ebx                     ; instance
   
   add ebx, [ebp+0x14]          ; new entrypoint
   call ebx                     ; call entrypoint

error:  
   pop edi
   pop esi
   pop ebx
   
   add esp,0x34
   pop ebp
   ret 0x20

_veh:
   mov eax,0xFFFFFFFF
   ret 4
