   [BITS 32]

   global _start

_start:  
   ;; == args ==
   ;; ebp+0x8: PVOID DllHandle
   ;; ebp+0xC: DWORD Reason
   ;; ebp+0x10: PVOID Reserved

   jmp short pre_oep            ; this will get patched out before oep
   
   push ebp
   mov ebp,esp
   
   mov eax, [0xDEADBEEF] ; address of callback in the callback array of the unpacked binary
   test eax,eax
   jz no_callback

   push dword [ebp+0x10]              ; PVOID Reserved
   push dword [ebp+0xC]               ; DWORD Reason
   push dword [ebp+0x8]               ; PVOID DllHandle
   call eax                               ; call the TLS callback

no_callback:
   pop ebp
   
pre_oep: 
   ret 0xC
