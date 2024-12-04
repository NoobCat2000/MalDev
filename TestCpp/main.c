#include <WinSock2.h>
#include <Windows.h>
#include <stdio.h>
#include <mstcpip.h>

#define ALLOC(X) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, X)
#define FREE(X) HeapFree(GetProcessHeap(), 0, X)

VOID HexDump
(
	_In_ PBYTE pBuffer,
	_In_ DWORD cbBuffer
)
{
	DWORD i, j;
	for (i = 0; i < cbBuffer; i += 16) {
		printf("%08x  ", i);
		for (j = 0; j < 16; j++) {
			if (i + j < cbBuffer) {
				printf("%02x ", pBuffer[i + j]);
			}
			else {
				printf("   ");
			}
		}

		printf(" |");
		for (j = 0; j < 16; j++) {
			if (i + j < cbBuffer) {
				printf("%c", isprint(pBuffer[i + j]) ? pBuffer[i + j] : '.');
			}
			else {
				printf(" ");
			}
		}

		printf("|\n");
	}
}

LPSTR DuplicateStrA
(
	_In_ LPSTR lpInput,
	_In_ DWORD dwAdditionalLength
)
{
	LPSTR lpResult = NULL;
	DWORD cbInput = 0;

	if (lpInput == NULL) {
		return ALLOC(sizeof(CHAR));
	}

	cbInput = lstrlenA(lpInput);
	if (dwAdditionalLength == 0) {
		lpResult = (LPSTR)ALLOC(cbInput + 1);
	}
	else {
		lpResult = (LPSTR)ALLOC(cbInput + 1 + dwAdditionalLength);
	}

	lstrcpyA(lpResult, lpInput);
	return lpResult;
}

VOID SniffOnInterface
(
	_In_ LPSTR lpAddr
)
{
	SOCKET Sock = INVALID_SOCKET;
	struct sockaddr SockAddr;
	DWORD dwOptValue = 1;
	BYTE Buffer[0x2000];
	struct sockaddr From;
	DWORD cbFrom = 0;
	DWORD dwNumberOfBytesRead = 0;

	Sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (Sock == INVALID_SOCKET) {
		goto CLEANUP;
	}

	SecureZeroMemory(&SockAddr, sizeof(SockAddr));
	SockAddr.sa_family = AF_INET;
	*((PDWORD)&SockAddr.sa_data[2]) = inet_addr(lpAddr);
	if (bind(Sock, &SockAddr, sizeof(SockAddr))) {
		printf("bind failed (Error: 0x%08x)", WSAGetLastError());
		goto CLEANUP;
	}

	if (WSAIoctl(Sock, SIO_RCVALL, &dwOptValue, sizeof(dwOptValue), NULL, 0, (LPDWORD)&SockAddr.sa_family, 0LL, 0LL)) {
		printf("WSAIoctl failed (Error: 0x%08x)", WSAGetLastError());
		goto CLEANUP;
	}

	while (TRUE) {
		cbFrom = sizeof(From);
		dwNumberOfBytesRead = recvfrom(Sock, Buffer, _countof(Buffer), 0, &From, &cbFrom);
		puts("-----------------------------");
		if (dwNumberOfBytesRead > 0x400) {
			HexDump(Buffer, 0x400);
		}
		else {
			HexDump(Buffer, dwNumberOfBytesRead);
		}
	}

CLEANUP:
	if (Sock != INVALID_SOCKET) {
		closesocket(Sock);
	}
}

int main() {
	WSADATA WsaData;
	CHAR szHostname[0x40];
	struct hostent* HostInfo = NULL;
	DWORD i = 0;
	LPSTR lpAddr = NULL;
	DWORD dwThreadID = 0;
	HANDLE hThread = NULL;

	if (WSAStartup(MAKEWORD(2, 2), &WsaData)) {
		return -1;
	}

	if (gethostname(szHostname, _countof(szHostname))) {
		return -1;
	}

	HostInfo = gethostbyname(szHostname);
	if (HostInfo == NULL) {
		return -1;
	}

	if (HostInfo->h_addr_list != NULL) {
		do {
			lpAddr = inet_ntoa(*(struct in_addr*)HostInfo->h_addr_list[i]);
			if (lstrcmpA(lpAddr, "127.0.0.1")) {
				hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SniffOnInterface, DuplicateStrA(lpAddr, 0), 0, &dwThreadID);
				break;
			}
			i++;
		} while (HostInfo->h_addr_list[i]);

		WaitForSingleObject(hThread, INFINITE);
	}

	return 0;
}