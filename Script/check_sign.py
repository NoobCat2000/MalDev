import subprocess
import os

def verify_sig(path: str):
    sigcheck64 = 'D:\App\Reversing Tools\SysinternalsSuite\sigcheck64.exe'
    output = subprocess.check_output([sigcheck64, path])
    if b'Verified:\tSigned' in output:
        return True
    else:
        return False

def list_dir(path: str):
    try:
        for entry in os.listdir(path):
            full_path = os.path.join(path, entry)
            if os.path.isdir(full_path):
                list_dir(full_path)
            elif entry.endswith('.exe'):
                print(full_path)
    except:
        return

list_dir('C:\\')