from pwn import *

session = ssh('random', 'pwnable.kr', port=2222, password='guest')

# If no seed is explicitly given, when rand() is called the prng is seeded
# with 1. GDB can be used to get the int returned from the rand() call.
rand = 0x6b8b4567
desired_value = 0xdeadbeef
key = rand ^ desired_value

io = session.process('./random')
io.sendline(str(key))

# Burn the "Good\n" message.
io.recvline()
# And print the flag.
print(io.recvline())
