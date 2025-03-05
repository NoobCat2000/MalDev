#pragma once

//typedef struct _SLIVER_PIPE_CLIENT {
//	LPSTR lpBindAddress;
//	DWORD dwWriteDeadline;
//	DWORD dwReadDeadline;
//	HANDLE hPipe;
//	PCRITICAL_SECTION pReadLock;
//	PCRITICAL_SECTION pWriteLock;
//	DWORD dwBufferSize;
//} SLIVER_PIPE_CLIENT, * PSLIVER_PIPE_CLIENT;
//
//PSLIVER_PIPE_CLIENT PipeInit();
//
//BOOL PipeCleanup
//(
//	_In_ PSLIVER_PIPE_CLIENT pTcpClient
//);
//
//BOOL PipeClose
//(
//	_In_ PSLIVER_PIPE_CLIENT pSliverTcpClient
//);
//
//BOOL PipeStart
//(
//	_In_ PGLOBAL_CONFIG pConfig,
//	_In_ PSLIVER_PIPE_CLIENT pTcpClient
//);
//
//PENVELOPE PipeRecv
//(
//	_In_ PGLOBAL_CONFIG pConfig,
//	_In_ PSLIVER_PIPE_CLIENT pTcpClient
//);
//
//BOOL PipeSend
//(
//	_In_ PGLOBAL_CONFIG pConfig,
//	_In_ PSLIVER_PIPE_CLIENT pTcpClient,
//	_In_ PENVELOPE pEnvelope
//);
//
//PPIVOT_LISTENER CreatePipePivotListener
//(
//	_In_ PGLOBAL_CONFIG pConfig,
//	_In_ LPVOID lpClient,
//	_In_ LPSTR lpBindAddress
//);