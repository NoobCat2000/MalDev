from Crypto.Cipher import ARC4

path = 'C:\\Users\\Admin\\AppData\\Local\\Temp\\EL.txt'
# path = 'C:\\Users\\Admin\\Desktop\\EL.txt'
data = open(path, 'rb').read()
rc4 = ARC4.new(b'LogKey')
print(rc4.decrypt(data).decode())