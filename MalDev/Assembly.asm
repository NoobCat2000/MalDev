.code

IndirectCall PROC
	push rax
	push rbx
	push rsi
	push rdi
	push rbp
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	mov rax, 01122334455667788h
	mov rbx, gs:[030h]
	add rbx, 01A00h
	mov rcx
	
IndirectCall ENDP

END