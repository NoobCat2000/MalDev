import sys

content = open(sys.argv[1], 'r').read()
lines = content.split('\n')
result = ''
for line in lines:
    line = line.replace('\\', '\\\\"')
    line = line.replace('"', '\\"')
    result += line + '\\n'

open('output.txt', 'w').write(result)