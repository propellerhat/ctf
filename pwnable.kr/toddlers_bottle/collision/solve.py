from pwn import *

session = ssh('col', 'pwnable.kr', port=2222, password='guest')

# Our goal is to sum 5 integers and get 0x21dd09ec.
desired_value = p32(0x21DD09EC)

# Since we must pass a strlen, the easy solution of just sending 0x21dd09ec
# and 4 more ints that are all zero won't work. We have to do the next best
# thing...

# We can send 0x01 values for each byte for the first four ints, and send the
# fifth int with each byte being 4 less than the target. This works since
# there won't be any carry or borrow.
solution = b'\x01' * 16

# Now calculate the fifth and final int to send.
fifth_integer = [byte - 4 for byte in desired_value]
solution += bytes(fifth_integer)

io = session.process(['./col', solution])
print(io.recvline())
