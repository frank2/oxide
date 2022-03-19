   [BITS 64]

   global _start

_start:
   ret

   mov rax, 0xDEADBEEFFACEBABE
   mov rax, [rax]
   test rax,rax
   jz no_callback

   call rax

no_callback:
   ret
