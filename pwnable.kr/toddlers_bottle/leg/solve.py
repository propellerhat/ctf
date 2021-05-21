from pwn import *

session = ssh('leg', 'pwnable.kr', port=2222, password='guest')

# No python on remote, so we must use ssh.run(). Launching the challenge
# binary directloy didn't seem to work. It's a QEMU instance and it could
# just be tempermental.
io = session.run('/bin/sh')

# key1() juts returns the pc at a particular point. ARM is baffling in that
# pc is usually ahead by two instructions in ARM mode.
key1 = 0x8ce4

# key2() gets a little fancy by bxing into Thumb mode. In this mode, pc is
# ahead of the currently executing instruction by 4 (2 Thumb instructions).
key2 = 0x8d0c

# key3() is the simplest in that it returns the link register, which will be
# the return address. The next address after the call to key3(), that is.
key3 = 0x8d80

# This is a QEMU instance and it's very noisy. We need to consume over 100
# junk lines before we get down to business and the shell actually displays
# a prompt.
io.recvuntil('/ $ ')

# Spawn the challenge binary.
io.sendline('./leg')

# Send the key
io.sendline(str(key1 + key2 + key3))
io.recvuntil('Congratz!\r\r\n')
print(io.recvline())
