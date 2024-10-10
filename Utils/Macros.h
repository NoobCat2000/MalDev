#pragma once

#define SEED 0x15
typedef VOID(WINAPI* EVENTSINK_CALLBACK)(BSTR lpInput, LPVOID Arg);

typedef struct _BUFFER {
	PBYTE pBuffer;
	DWORD cbBuffer;
} BUFFER, * PBUFFER;