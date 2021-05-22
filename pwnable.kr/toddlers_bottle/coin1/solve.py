from pwn import *
from parse import parse

def find_coin(r, start, end):
  pivot = start + int((end - start) / 2)
  coins = [str(number) for number in range(start, pivot + 1)]
  r.sendline(' '.join(coins))
  response = r.recvline(False)
  if response.startswith(b'Correct!'):
    return
  if ((int(response) % 10) == 0):
    find_coin(r, pivot + 1, end)
  else:
    find_coin(r, start, pivot)

r = remote('pwnable.kr', 9007)
r.recvuntil('starting in 3 sec... -\n')
r.recvline()

coins_found = 0

while (coins_found < 100):
  n, c = parse('N={} C={}', r.recvline(False).decode('utf-8'))
  find_coin(r, 0, int(n) - 1)
  coins_found += 1
  log.info('Coins found: {}'.format(coins_found))

r.recvline()
print(r.recvline())
