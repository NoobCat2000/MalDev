from capstone import *
import subprocess

main_machine_code = open('.\\build\\main.exe', 'rb').read()[0x400:0x140134b10]
cs = Cs(CS_ARCH_X86, CS_MODE_64)
cs.detail = True
asm = ''
for insn in cs.disasm(main_machine_code, 0x14001000):
    asm += f'{insn.address:#x}:{insn.mnemonic} {insn.op_str}\n'

open('code.asm', 'w').write(asm)