#pragma once

#ifdef _FULL
typedef struct _SLIVER_TCP_CLIENT {
	PPIVOT_PROFILE pProfile;
	SOCKET Sock;
	PCRITICAL_SECTION pReadLock;
	PCRITICAL_SECTION pWriteLock;
} SLIVER_TCP_CLIENT, *PSLIVER_TCP_CLIENT;

PSLIVER_TCP_CLIENT TcpInit
(
	_In_ PPIVOT_PROFILE pProfile
);

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

PPIVOT_LISTENER CreateTCPPivotListener
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ LPVOID lpClient,
	_In_ LPSTR lpBindAddress
);

#endif