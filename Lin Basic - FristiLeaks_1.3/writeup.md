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

### Сохраняю имена в файл
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


