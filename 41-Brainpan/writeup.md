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
```
                             **************************************************************
                             * get_reply                                                  *
                             **************************************************************
                             undefined __cdecl get_reply(char * param_1)
             undefined         <UNASSIGNED>        <RETURN>
             char *            Stack[0x4]:4        param_1                                 XREF[2]:     31171305(R), 
             undefined1        Stack[-0x20c]:520   local_20c                               XREF[3]:     3117131f(*), 
```
`param_1` - это 32 битный указатель (char *), длиной 4 байта, далее идет EBP (тоже 4 байта в 32 битной архитектуре) и адрес возврата.  
  
т.е. для изменения адреса возврата, в переменную `local_20c` нужно положить 520 байт,  
следующие 4 байта перезапишут указатель `param_1`,  
ещё 4 байта перезапишут `EBP`,  
и ещё 4 байта перезапишут `return adress`  
  
Итого: **520**(local_20c) + **4**(param_1) + **4**(EBP) + **4**(return)

Тоже самое можно понять по `Stack[-0x20c]:520   local_20c`.
Ghidra указывает смещение относительно EBP: `EBP-0x20c`.
`0x20c` = `524` в десятичной системе
<img width="646" height="268" alt="image" src="https://github.com/user-attachments/assets/ff1ab201-d2aa-41d1-8145-532468db6179" />

  
```bash
[EBP - 0x20C] local_20c      (520 байт)
[EBP - 0x218] local_218      (4 байта)
[EBP - 0x21C] local_21c      (4 байта)
[EBP + 0x00] saved EBP       (4 байта)
[EBP + 0x04] return address  (4 байта)
```

Нужно записать 200*NOP + payload + 



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


