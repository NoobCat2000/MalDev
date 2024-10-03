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

END