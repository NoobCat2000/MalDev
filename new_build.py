import subprocess
import os
import datetime
import time
import sys
import shutil

ml64_args = ['ml64.exe', '/Fo', 'build\\obfuscated-build\\Assembly.obj', '/c', 'Utils\\Assembly.asm']
# opt_args = ['opt', '-S', '--load-pass-plugin=D:\\Temp\\vs-windows-llvm\\build\\lib\\Debug\\vs-windows-llvm.dll', '--passes=my-obf-str,hashing,new-flattening', '.\\build\\main.ll']
opt_args = ['opt', '-S', '--load-pass-plugin=D:\\Temp\\vs-windows-llvm\\build\\lib\\Debug\\vs-windows-llvm.dll', '--passes=new-flattening', '.\\build\\main.ll']
llc_args = ['llc', '-filetype=obj', '-O0', '.\\build\\obfuscated-build\\main.ll']
pdb_path = os.getcwd() + "\\main.pdb"
lld_args = ['lld-link', '/debug', '/SUBSYSTEM:CONSOLE', '/machine:X64', '/dynamicbase:no', '/entry:main', '/incremental:no', '/libpath:"C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.22621.0\\um\\x64\\"', '/out:..\\..\\x64\\Debug\\FinalTest.exe']
libs = ['DnsAPI.lib', 'Gdi32.lib', 'ktmw32.lib', 'UserEnv.lib', 'RpcRT4.lib', 'user32.lib', 'kernel32.lib', 'shell32.lib', 'Version.lib', 'iphlpapi.lib', 'oleaut32.lib', 'msvcrt.lib', 'comdlg32.lib', 'dbghelp.lib', 'Ole32.lib', 'ws2_32.lib', 'crypt32.lib', 'taskschd.lib', 'wbemuuid.lib', 'bcrypt.lib', 'ntdll.lib', 'libucrtd.lib', 'winhttp.lib', 'ShLwApi.lib', 'strsafe.lib', 'wininet.lib', 'advapi32.lib', 'wtsapi32.lib']
targeted_dir = ['Test', 'Utils']

def print_list(l: list):
    print('Run: ', end='')
    for i in l:
        print(i + ' ', end='')

    print('')

def build(project: str):
    os.chdir('.\\build\\final')
    libs = []
    for file in os.listdir('..\\..\\' + project):
        if file.endswith(".c") or file.endswith(".asm"):
            name = file.split(".")[0]
            libs.append(name + '.obj')
    
    lld_args.append(f'{project}.lib')
    libs.append(f'/out:{project}.lib')
    print_list(libs)
    subprocess.run(['llvm-lib'] + libs)
    os.chdir('..\\..')

for file in os.listdir('.\\build\\obfuscated-build'):
    if file.endswith(".ll"):
        name = file.split(".")[0]
        opt_args[-1] = f'.\\build\\obfuscated-build\\{name}.ll'
        llc_args[-1] = f'.\\build\\final\\{name}.ll'
        print_list(opt_args)
        result = subprocess.run(opt_args, stdout=subprocess.PIPE)
        open(llc_args[-1], 'wb').write(result.stdout)
        subprocess.run(llc_args)
    elif file.endswith(".obj"):
        name = file.split(".")[0]
        if not os.path.exists(f'.\\build\\obfuscated-build\\{name}.ll'):
            shutil.copy(f'.\\build\\obfuscated-build\\{file}', f'.\\build\\final\\{name}.obj')

build('Test')
build('Utils')
os.chdir('.\\build\\final')
print_list(lld_args + libs)
subprocess.run(lld_args + libs)