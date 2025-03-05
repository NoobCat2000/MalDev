.code

IndirectCall PROC
	mov rax, QWORD PTR [rsp]
	mov QWORD PTR [rdx + 0100h], rax
	mov QWORD PTR [rdx + 0108h], rsp
	mov rsp, rdx
	mov QWORD PTR [rsp + 0110h], rdx
	mov QWORD PTR [rsp + 0118h], r8
	mov QWORD PTR [rsp + 0120h], r9
	mov rax, rcx
	mov rcx, QWORD PTR [rsp]
	mov rdx, QWORD PTR [rdx + 8]
	mov r8, QWORD PTR [rsp + 16]
	mov r9, QWORD PTR [rsp + 24]
	call rax
	mov rdx, QWORD PTR [rsp + 0110h]
	mov rsp, QWORD PTR [rdx + 0108h]
	mov rcx, QWORD PTR [rdx + 0100h]
	mov QWORD PTR [rsp], rcx
	mov r8, QWORD PTR [rdx + 0118h]
	mov r9, QWORD PTR [rdx + 0120h]
	mov DWORD PTR [rdx - 16], 0CCCCCCCCh
	mov DWORD PTR [rdx - 12], 0CCCCCCCCh
	mov DWORD PTR [rdx - 8], 0CCCCCCCCh
	mov DWORD PTR [rdx - 4], 0CCCCCCCCh
	ret
IndirectCall ENDP

SPOOFER STRUCT
    FirstFrameFunctionPointer       DQ 1
    SecondFrameFunctionPointer      DQ 1
    JmpRbxGadget                    DQ 1
    AddRspXGadget                   DQ 1
    FirstFrameSize                  DQ 1
    FirstFrameRandomOffset          DQ 1
    SecondFrameSize                 DQ 1
    SecondFrameRandomOffset         DQ 1
    JmpRbxGadgetFrameSize           DQ 1
    AddRspXGadgetFrameSize          DQ 1
    StackOffsetWhereRbpIsPushed     DQ 1
    FirstFramePointerOffset         DQ 1
    ReturnAddress                   DQ 1
SPOOFER ENDS

; GetCurrentRsp PROC
;     mov rax, rsp
;     add rax, 8
;     ret
; GetCurrentRsp ENDP

RestoreState PROC
	mov rsp, rbp
	mov rbp, QWORD PTR [rsp + 08h]
	mov rbx, QWORD PTR [rsp + 010h]
	ret
RestoreState ENDP

SpooferConfig SPOOFER <?>

SpoofCall PROC
    lea r10, SpooferConfig
    mov rax, 01122334455667788h
    mov QWORD PTR [r10].SPOOFER.FirstFrameFunctionPointer, rax
    mov rax, 01122334455667788h
    mov QWORD PTR [r10].SPOOFER.SecondFrameFunctionPointer, rax
    mov rax, 01122334455667788h
    mov QWORD PTR [r10].SPOOFER.JmpRbxGadget, rax
    mov rax, 01122334455667788h
    mov QWORD PTR [r10].SPOOFER.AddRspXGadget, rax
    mov rax, 01122334455667788h
    mov QWORD PTR [r10].SPOOFER.FirstFrameSize, rax
    mov rax, 01122334455667788h
    mov QWORD PTR [r10].SPOOFER.FirstFrameRandomOffset, rax
    mov rax, 01122334455667788h
    mov QWORD PTR [r10].SPOOFER.SecondFrameSize, rax
    mov rax, 01122334455667788h
    mov QWORD PTR [r10].SPOOFER.SecondFrameRandomOffset, rax
    mov rax, 01122334455667788h
    mov QWORD PTR [r10].SPOOFER.JmpRbxGadgetFrameSize, rax
    mov rax, 01122334455667788h
    mov QWORD PTR [r10].SPOOFER.AddRspXGadgetFrameSize, rax
    mov rax, 01122334455667788h
    mov QWORD PTR [r10].SPOOFER.StackOffsetWhereRbpIsPushed, rax
    mov rax, 01122334455667788h
    mov QWORD PTR [r10].SPOOFER.ReturnAddress, rax
    mov rax, 01122334455667788h
    mov QWORD PTR [r10].SPOOFER.FirstFramePointerOffset, rax
    
    mov QWORD PTR [rsp + 08h], rbp
	mov QWORD PTR [rsp + 010h], rbx

    ; mov	rbx, QWORD PTR [r10].SPOOFER.JmpRbxGadget
	; mov QWORD PTR [rsp + 018h], rbx
	; lea	rbx, [rsp + 018h]
	; mov	[r10].SPOOFER.JmpRbxGadgetRef, rbx

    mov rbp, rsp
    mov QWORD PTR [rbp - 010h], rcx
    mov QWORD PTR [rbp - 018h], rdx
    mov QWORD PTR [rbp - 020h], r8
    mov QWORD PTR [rbp - 028h], r9

    lea rax, RestoreState
    push rax
    lea  rbx, [rsp]
    sub rsp, 01000h

    push [r10].SPOOFER.FirstFrameFunctionPointer
	mov rax, QWORD PTR [r10].SPOOFER.FirstFrameRandomOffset
	add QWORD PTR [rsp], rax
	mov rax, [r10].SPOOFER.ReturnAddress
	sub rax, [r10].SPOOFER.FirstFrameSize
    add rax, [r10].SPOOFER.FirstFramePointerOffset
	sub rsp, [r10].SPOOFER.SecondFrameSize
	mov rcx, [r10].SPOOFER.StackOffsetWhereRbpIsPushed
	mov [rsp + rcx], rax

    push [r10].SPOOFER.SecondFrameFunctionPointer
    mov rax, QWORD PTR [r10].SPOOFER.SecondFrameRandomOffset
    add qword ptr [rsp], rax

    sub rsp, [r10].SPOOFER.JmpRbxGadgetFrameSize
	; push [r10].SPOOFER.JmpRbxGadgetRef
	push [r10].SPOOFER.JmpRbxGadget
	sub rsp, [r10].SPOOFER.AddRspXGadgetFrameSize

    push [r10].SPOOFER.AddRspXGadget
    mov rcx, QWORD PTR [rbp - 018h]
    mov rdx, QWORD PTR [rbp - 020h]
    mov r8, QWORD PTR [rbp - 028h]
    mov r9, QWORD PTR [rbp + 028h]

    mov rax, QWORD PTR [rbp + 030h]
    mov QWORD PTR [rsp + 028h], rax
    
    mov rax, QWORD PTR [rbp + 038h]
    mov QWORD PTR [rsp + 030h], rax

    mov rax, QWORD PTR [rbp + 040h]
    mov QWORD PTR [rsp + 038h], rax

    mov rax, QWORD PTR [rbp + 048h]
    mov QWORD PTR [rsp + 040h], rax

    mov rax, QWORD PTR [rbp + 050h]
    mov QWORD PTR [rsp + 048h], rax
    
    mov rax, QWORD PTR [rbp + 058h]
    mov QWORD PTR [rsp + 050h], rax

    mov rax, QWORD PTR [rbp + 060h]
    mov QWORD PTR [rsp + 058h], rax

    mov rax, QWORD PTR [rbp + 068h]
    mov QWORD PTR [rsp + 060h], rax

    mov rax, QWORD PTR [rbp - 010h]
    jmp rax
SpoofCall ENDP

END