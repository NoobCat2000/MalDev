#pragma once

typedef struct _SLIVER_TCP_CLIENT {
	LPSTR lpHost;
	DWORD dwPort;
	DWORD dwWriteDeadline;
	DWORD dwReadDeadline;
	SOCKET Sock;
	CRITICAL_SECTION Lock;
} SLIVER_TCP_CLIENT, *PSLIVER_TCP_CLIENT;

PSLIVER_TCP_CLIENT TcpInit();

BOOL TcpCleanup
(
	_In_ PSLIVER_TCP_CLIENT pTcpClient
);

BOOL TcpClose
(
	_In_ PSLIVER_TCP_CLIENT pSliverTcpClient
);

BOOL TcpStart
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_TCP_CLIENT pTcpClient
);

PENVELOPE TcpRecv
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_TCP_CLIENT pTcpClient
);

BOOL TcpSend
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_TCP_CLIENT pTcpClient,
	_In_ PENVELOPE pEnvelope
);