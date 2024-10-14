section .text
global _global_text_sym
_global_text_sym:
dd 42
_local_text_sym:
dd 42

extern _external_weak_sym:weak
dd _external_weak_sym

extern _external_weak_object:weak object
dd _external_weak_object

extern _global_weak_object:weak object
_global_weak_object:
dd _global_weak_object

section .rodata
global _global_rodata_sym
_global_rodata_sym:
dd 42
_local_rodata_sym:
dd 42

section .data
global _global_data_sym
_global_data_sym:
dd 42
_local_data_sym:
dd 42

extern _extern_sym
dd _extern_sym

section .bss
global _global_bss_sym
_global_bss_sym:
resb 0x4
_local_bss_sym:
resb 0x4

common _common_sym 42

global _global_weak_sym:weak
_global_weak_sym:
resb 0x4

; it appears that nm detects special section names like ".debug" and changes the
; symbol characters with it. I honestly can't be bothered to find every single
; edgecase, but you can see the effect by changing ".foo" to ".debug" below here
section .foo nowrite noalloc
global _global_debug_sym
_global_debug_sym:
dd 0x4
_local_debug_sym:
dd 0x4

section .nobits nowrite noalloc noexec nobits
global _global_nobits
_global_nobits_sym:
resb 0x4
_local_nobits_sym:
resb 0x4

section .comment
global _global_comment
_global_comment_sym:
dd 0x4
_local_comment_sym:
dd 0x4

section .note:
global _global_note
_global_note_sym:
dd 0x4
_local_note_sym:
dd 0x4

section .exec exec progbits
global _global_executable_sym
_global_executable_sym:
dd 0x4
_local_executable_sym:
dd 0x4
