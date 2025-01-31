import sys
import pefile

pe = pefile.PE(sys.argv[1])
for section in pe.sections:
    # print(dir(section))
    if b'.text' in section.Name:
        section.Characteristics |= 0x80000000

data = pe.write()
pe.close()
with open(sys.argv[1], 'wb') as f:
    f.write(bytes(data))