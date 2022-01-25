PUBLIC Enable_VMX_Operation_asm
PUBLIC Breakpoint
PUBLIC STI_Instruction
PUBLIC CLI_Instruction
PUBLIC INVEPT_Instruction
PUBLIC GetCs
PUBLIC GetDs
PUBLIC GetEs
PUBLIC GetSs
PUBLIC GetFs
PUBLIC GetGs
PUBLIC GetLdtr
PUBLIC GetTr
PUBLIC Get_GDT_Base
PUBLIC Get_IDT_Base
PUBLIC Get_GDT_Limit
PUBLIC Get_IDT_Limit
PUBLIC Get_RFLAGS
PUBLIC Restore_To_VMXOFF_State_asm
PUBLIC Save_VMXOFF_State_asm
PUBLIC __load_ar

EXTERN global_StackPointerForReturning:QWORD
EXTERN global_BasePointerForReturning:QWORD


.code _text


;------------------------------------------------------------------------
    VMX_ERROR_CODE_SUCCESS              = 0
    VMX_ERROR_CODE_FAILED_WITH_STATUS   = 1
    VMX_ERROR_CODE_FAILED               = 2
;------------------------------------------------------------------------

Enable_VMX_Operation_asm PROC PUBLIC
push rax			; Save the state

xor rax,rax			; Clear the RAX
mov rax,cr4
or rax,02000h		; Set the 14th bit
mov cr4,rax

pop rax				; Restore the state
ret
Enable_VMX_Operation_asm ENDP

;------------------------------------------------------------------------
     
Breakpoint PROC PUBLIC
int 3
ret
Breakpoint ENDP 

;------------------------------------------------------------------------

STI_Instruction PROC PUBLIC
STI
ret
STI_Instruction ENDP 

;------------------------------------------------------------------------

CLI_Instruction PROC PUBLIC
CLI
ret
CLI_Instruction ENDP 
;------------------------------------------------------------------------

Restore_To_VMXOFF_State_asm PROC PUBLIC

VMXOFF  ; turn it off before exiting

MOV rsp, global_StackPointerForReturning
MOV rbp, global_BasePointerForReturning

; make rsp point to a correct return point
ADD rsp,8

; return True
xor rax,rax
mov rax,1

; return section

mov     rbx, [rsp+28h+8h]
mov     rsi, [rsp+28h+10h]
add     rsp, 040h
pop     rdi

ret

Restore_To_VMXOFF_State_asm ENDP 

;------------------------------------------------------------------------

Save_VMXOFF_State_asm PROC PUBLIC
MOV global_StackPointerForReturning,rsp
MOV global_BasePointerForReturning,rbp
ret

Save_VMXOFF_State_asm ENDP 

;------------------------------------------------------------------------
INVEPT_Instruction PROC PUBLIC
        invept  rcx, oword ptr [rdx]
        jz @jz
        jc @jc
        xor     rax, rax
        ret

@jz:    mov     rax, VMX_ERROR_CODE_FAILED_WITH_STATUS
        ret

@jc:    mov     rax, VMX_ERROR_CODE_FAILED
        ret
INVEPT_Instruction ENDP

;------------------------------------------------------------------------
Get_GDT_Base PROC
	LOCAL	gdtr[10]:BYTE
	sgdt	gdtr
	mov		rax, QWORD PTR gdtr[2]
	ret
Get_GDT_Base ENDP
;------------------------------------------------------------------------
GetCs PROC
	mov		rax, cs
	ret
GetCs ENDP
;------------------------------------------------------------------------
GetDs PROC
	mov		rax, ds
	ret
GetDs ENDP
;------------------------------------------------------------------------
GetEs PROC
	mov		rax, es
	ret
GetEs ENDP
;------------------------------------------------------------------------
GetSs PROC
	mov		rax, ss
	ret
GetSs ENDP
;------------------------------------------------------------------------
GetFs PROC
	mov		rax, fs
	ret
GetFs ENDP
;------------------------------------------------------------------------
GetGs PROC
	mov		rax, gs
	ret
GetGs ENDP
;------------------------------------------------------------------------
GetLdtr PROC
	sldt	rax
	ret
GetLdtr ENDP
;------------------------------------------------------------------------
GetTr PROC
	str	rax
	ret
GetTr ENDP
;------------------------------------------------------------------------
Get_IDT_Base PROC
	LOCAL	idtr[10]:BYTE
	
	sidt	idtr
	mov		rax, QWORD PTR idtr[2]
	ret
Get_IDT_Base ENDP
;------------------------------------------------------------------------

Get_GDT_Limit PROC
	LOCAL	gdtr[10]:BYTE

	sgdt	gdtr
	mov		ax, WORD PTR gdtr[0]
	ret
Get_GDT_Limit ENDP

;------------------------------------------------------------------------
Get_IDT_Limit PROC
	LOCAL	idtr[10]:BYTE
	
	sidt	idtr
	mov		ax, WORD PTR idtr[0]
	ret
Get_IDT_Limit ENDP
;------------------------------------------------------------------------
Get_RFLAGS PROC
	pushfq
	pop		rax
	ret
Get_RFLAGS ENDP
;------------------------------------------------------------------------
__load_ar PROC
        lar     rax, rcx
        jz      no_error
        xor     rax, rax
no_error:
        ret
__load_ar ENDP
;------------------------------------------------------------------------
END