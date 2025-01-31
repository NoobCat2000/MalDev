import subprocess
import os
import datetime
import time
import sys

clang_args = ["clang", "-O0", "-fno-strict-float-cast-overflow", "-fno-stack-protector", "-emit-llvm", "-S", "Test\\main.c", "-femit-all-decls", "-D", "_DEBUG", "-I", "D:\\App\\Dev Tools\\systeminformer\\phnt\\include", "-I", ".\\Utils", "-disable-O0-optnone", "-o", ".\\build\\main.ll"]
# clang_args = ["clang", "-O0", "-fno-strict-float-cast-overflow", "-fno-stack-protector", "-emit-llvm", "-S", "Test\\main.c", "-femit-all-decls", "-I", "D:\\App\\Dev Tools\\systeminformer\\phnt\\include", "-I", ".\\Utils", "-disable-O0-optnone", "-o", ".\\build\\main.ll"]
ml64_args = ['ml64.exe', '/Fo', 'build\\obfuscated-build\\Assembly.obj', '/c', 'Utils\\Assembly.asm']
# opt_args = ['opt', '-S', '--load-pass-plugin=D:\\Temp\\vs-windows-llvm\\build\\lib\\Debug\\vs-windows-llvm.dll', '--passes=my-obf-str,hashing,new-flattening', '.\\build\\main.ll']
opt_args = ['opt', '-S', '--load-pass-plugin=D:\\Temp\\vs-windows-llvm\\build\\lib\\Debug\\vs-windows-llvm.dll', '--passes=my-obf-str,hashing,new-flattening', '.\\build\\main.ll']
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
    c_files = []
    for file in os.listdir(project):
        if file.endswith(".c"):
            c_files.append(file)
        elif file.endswith('.asm'):
            name = file.split(".")[0]
            ml64_args[-1] = project + "\\" + file
            ml64_args[2] = "build\\obfuscated-build\\" + name + '.obj'
            print_list(ml64_args)
            subprocess.run(ml64_args, stderr=subprocess.DEVNULL)

    if 'LLVM.c' in c_files:
        c_files.append(c_files.pop(c_files.index('LLVM.c')))

    for file in c_files:
        name = file.split(".")[0]
        clang_args[6] = project + "\\" + file
        clang_args[-1] = f"build\\{name}.ll"
        opt_args[-1] = clang_args[-1]
        llc_args[-1] = f'.\\build\\obfuscated-build\\{name}.ll'

        if last_build_time != None:
            if os.path.exists(clang_args[-1]):
                last_compile_time = time.ctime(os.path.getmtime(clang_args[-1]))
                if time.strptime(last_compile_time) > last_build_time:
                    continue

        print_list(clang_args)
        subprocess.run(clang_args, stderr=subprocess.DEVNULL)
        print_list(opt_args)
        result = subprocess.run(opt_args, stdout=subprocess.PIPE)
        open(llc_args[-1], 'wb').write(result.stdout)
        subprocess.run(llc_args)

    os.chdir('.\\build\\obfuscated-build')
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

# utils_lib = ['Utils.obj', 'LLVM.obj', 'AVDetection.obj', 'Cryptography.obj', 'Curve25519.obj', 'EventSink.obj', 'Filesystem.obj', 'Gui.obj', 'Hash.obj', 'Image.obj', 'Persistence.obj', 'Process.obj', 'Protobuf.obj', 'Random.obj', 'Registry.obj', 'ScheduledTask.obj', 'Service.obj', 'StringHelper.obj', 'SystemInfo.obj', 'Time.obj', 'UACBypass.obj', 'Wmi.obj']
last_build_time = None
if len(sys.argv) > 1:
    last_build_time = datetime.datetime.strptime(sys.argv[1], "%d-%m %H:%M:%S").time()

build('Test')
# build('TestSideloading')
build('Utils')
os.chdir('.\\build\\obfuscated-build')
print_list(lld_args + libs)
subprocess.run(lld_args + libs)