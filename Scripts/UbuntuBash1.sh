clear
now="$(date +'%d/%m/%Y %r')"
echo "Running Main Ubuntu Script Team 15-4209 ($now)"
if (lsb_release -a 2>/dev/null | grep -q 16.04); then
    OS=u16
elif (lsb_release -a 2>/dev/null | grep -q 18.04); then
    OS=u18
elif (lsb_release -a 2>/dev/null | grep -q 20.04); then
    OS=u20
elif (lsb_release -a 2>/dev/null | grep -q 'Debian.* 8'); then
    OS=d8
elif (lsb_release -a 2>/dev/null | grep -q 'Debian.* 9'); then
    OS=d9
elif (lsb_release -a 2>/dev/null | grep -q 'Debian.* 10'); then
    OS=d10
elif (lsb_release -a 2>/dev/null | grep -q 'Debian.* 11'); then
    OS=d11
elif [[ $DRYRUN = true ]]; then
    OS=u18
else
    echo "Failed to identify OS version"
    return 1
fi
echo "Os = $OS"
read -p "Please do Forensics... [Press enter to continue]"

echo "TEAM 15-4209---------------------------"
echo "Linux Bash Script 1------------cc-nd-nc"
echo "11-2022------------------------------KC"

if [[ $EUID -ne 0 ]]
then
  echo "Root Privileges are needed to run this script."
  exit 1
fi

echo "Installing good programs..."
apt-get install clamav lynis rkhunter chkrootkit synaptic -y

read -p "[Press Enter To Start]"

echo "Dealing With Users..."
echo "Type all user account names, seperated by a space"
read -a users

usersLength=${#users[@]}	

for (( i=0;i<$usersLength;i++))
do
	echo "${users[${i}]}"
	echo "Delete ${users[${i}]}? [y/n]"
	read yn1
	if [ $yn1 == yes ]
	then
		userdel -r ${users[${i}]}
		echo "${users[${i}]} has been deleted."
	else	
		echo "Make ${users[${i}]} administrator? [y/n]"
		read yn2								
		if [ $yn2 == yes ]
		then
			gpasswd -a ${users[${i}]} sudo
			gpasswd -a ${users[${i}]} adm
			gpasswd -a ${users[${i}]} lpadmin
			gpasswd -a ${users[${i}]} sambashare
			echo "${users[${i}]} is now an Admin."
		else
			gpasswd -d ${users[${i}]} sudo
			gpasswd -d ${users[${i}]} adm
			gpasswd -d ${users[${i}]} lpadmin
			gpasswd -d ${users[${i}]} sambashare
			gpasswd -d ${users[${i}]} root
			echo "${users[${i}]} is now a standard user."
		fi
		passwd -x30 -n3 -w7 ${users[${i}]}
		usermod -L ${users[${i}]}
		echo "${users[${i}]}'s password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days. ${users[${i}]}'s account has been locked."
	fi
done

echo "Type user account names of new users you want to add, seperated by a space"
read -a usersNew

usersNewLength=${#usersNew[@]}	

for (( i=0;i<$usersNewLength;i++))
do
	echo "${usersNew[${i}]}"
	adduser ${usersNew[${i}]}
	echo "${usersNew[${i}]} account has been created"
	echo "Make ${usersNew[${i}]} An Administrator? [y/n]"
	read ynNew								
	if [ $ynNew == yes ]
	then
		gpasswd -a ${usersNew[${i}]} sudo
		gpasswd -a ${usersNew[${i}]} adm
		gpasswd -a ${usersNew[${i}]} lpadmin
		gpasswd -a ${usersNew[${i}]} sambashare
		echo "${usersNew[${i}]} is now an Admin."
	else
		echo "${usersNew[${i}]} is now a standard user."
	fi
	
	passwd -x30 -n3 -w7 ${usersNew[${i}]}
	usermod -L ${usersNew[${i}]}
	echo "${usersNew[${i}]}'s password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days. ${users[${i}]}'s account has been locked."
done

echo "Removing Alias..."
unalias -a

echo "Locking Root Account..."
usermod -L root

echo "Setting bash history file permissions..."
chmod 640 .bash_history

echo "Setting Read/Write permissions on shadow..."
chmod 604 /etc/shadow

echo "Updating shadow password configuration file..."
cp login.defs /etc/login.defs

echo "Updating PAM authentication file..."
cp common-auth /etc/pam.d/common-auth

echo "Updating PAM password file..."
cp common-password /etc/pam.d/common-password

echo "Removing GNOME games..."
apt-get -y purge gnome-games > /dev/null

echo "Listing files in user directories..."
find /home ~+ -type f -name "*" > userfiles.txt

echo "Removing games from /usr/..."
rm -rf /usr/games > /dev/null
rm -rf /usr/local/games > /dev/null

echo "Removing unneeded software..."
while read line; do
  apt-get -y purge $line &> /dev/null
done < software.txt

echo "Disabling unneeded services..."
while read line; do 
  systemctl stop $line &> /dev/null
  systemctl disable $line &> /dev/null
done < services.txt

echo "Restricting compiler access..."
chmod o-rx /usr/bin/x86_64-linux-gnu-as > /dev/null

echo "Setting shadow file permissions..."
chown root:shadow /etc/shadow
chmod 640 /etc/shadow

echo "Setting account file permissions..."
chown root:root /etc/passwd
chmod 644 /etc/passwd

echo "Setting group file permissions..."
chown root:root /etc/group
chmod 644 /etc/group

echo "Setting PAM file permissions..."
chown root:root /etc/pam.d
chmod 644 /etc/pam.d

echo "Setting group password file permissions..."
chown root:shadow /etc/gshadow
chmod 640 /etc/gshadow

echo "Setting Cron file permissions..."
chmod 600 /etc/crontab
chmod 700 /etc/cron.d
chmod 700 /etc/cron.daily
chmod 700 /etc/cron.hourly
chmod 700 /etc/cron.monthly
chmod 700 /etc/cron.weekly

echo "Disabling core dumps..."
cp limits.conf /etc/security/limits.conf

echo "Setting hosts file to defaults..."
chmod 777 /etc/hosts
cp /etc/hosts ~/Desktop/backups/
echo > /etc/hosts
echo -e "127.0.0.1 localhost\n127.0.1.1 $USER\n::1 ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters" >> /etc/hosts
chmod 644 /etc/hosts

echo "Securing LightDM..."
chmod 777 /etc/lightdm/lightdm.conf
cp /etc/lightdm/lightdm.conf ~/Desktop/backups/
echo > /etc/lightdm/lightdm.conf
echo -e '[SeatDefaults]\nallow-guest=false\ngreeter-hide-users=true\ngreeter-show-manual-login=true' >> /etc/lightdm/lightdm.conf
chmod 644 /etc/lightdm/lightdm.conf

echo "Removing scripts in bin..."
find /bin/ -name "*.sh" -type f -delete

echo "Backing Up This Machine..."
mkdir -p ~/Desktop/backups
chmod 777 ~/Desktop/backups
echo "Backups Folder Created"

cp /etc/group ~/Desktop/backups/
chmod 777 ~/Desktop/backups/group
cp /etc/passwd ~/Desktop/backups/
chmod 777 ~/Desktop/backups/passwd
echo "/etc/group And /etc/passwd Files Are Backed Up"

echo "Installing Program Updates..."
apt-get -V -y install firefox hardinfo chkrootkit iptables portsentry lynis ufw gufw sysv-rc-conf nessus clamav
apt-get -V -y install --reinstall coreutils

echo "Securing Network..."
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 23 -j DROP         #Block Telnet
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 2049 -j DROP       #Block NFS
iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 2049 -j DROP       #Block NFS
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 6000:6009 -j DROP  #Block X-Windows
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 7100 -j DROP       #Block X-Windows font server
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 515 -j DROP        #Block printer port
iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 515 -j DROP        #Block printer port
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 111 -j DROP        #Block Sun rpc/NFS
iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 111 -j DROP        #Block Sun rpc/NFS
iptables -A INPUT -p all -s localhost  -i eth0 -j DROP            #Deny outside packets from internet which claim to be from your loopback interface.
ufw enable
ufw deny 23
ufw deny 2049
ufw deny 515
ufw deny 111
ufw logging high
ufw status verbose
lsof  -i -n -P
netstat -tulpn
echo "Backing up IPTables..."
mkdir /iptables/
touch /iptables/rules.v4.bak
touch /iptables/rules.v6.bak
iptables-save > /iptables/rules.v4.bak
ip6tables-save > /iptables/rules.v6.bak
echo "Clearing out IPTables..."
iptables -t nat -F
iptables -t mangle -F
iptables -t nat -X
iptables -t mangle -X
iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
ip6tables -t nat -F
ip6tables -t mangle -F
ip6tables -t nat -X
ip6tables -t mangle -X
ip6tables -F
ip6tables -X
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
echo "Blocking Bogons..."
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -s 100.64.0.0/10 -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 192.0.0.0/24 -j DROP
iptables -A INPUT -s 192.0.2.0/24 -j DROP
iptables -A INPUT -s 198.18.0.0/15 -j DROP
iptables -A INPUT -s 198.51.100.0/24 -j DROP
iptables -A INPUT -s 203.0.113.0/24 -j DROP
iptables -A INPUT -s 224.0.0.0/3 -j DROP
iptables -A OUTPUT -d 0.0.0.0/8 -j DROP
iptables -A OUTPUT -d 100.64.0.0/10 -j DROP
iptables -A OUTPUT -d 169.254.0.0/16 -j DROP
iptables -A OUTPUT -d 192.0.0.0/24 -j DROP
iptables -A OUTPUT -d 192.0.2.0/24 -j DROP
iptables -A OUTPUT -d 198.18.0.0/15 -j DROP
iptables -A OUTPUT -d 198.51.100.0/24 -j DROP
iptables -A OUTPUT -d 203.0.113.0/24 -j DROP
iptables -A OUTPUT -d 224.0.0.0/3 -j DROP
iptables -A OUTPUT -s 0.0.0.0/8 -j DROP
iptables -A OUTPUT -s 100.64.0.0/10 -j DROP
iptables -A OUTPUT -s 169.254.0.0/16 -j DROP
iptables -A OUTPUT -s 192.0.0.0/24 -j DROP
iptables -A OUTPUT -s 192.0.2.0/24 -j DROP
iptables -A OUTPUT -s 198.18.0.0/15 -j DROP
iptables -A OUTPUT -s 198.51.100.0/24 -j DROP
iptables -A OUTPUT -s 203.0.113.0/24 -j DROP
iptables -A OUTPUT -s 224.0.0.0/3 -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
iptables -A INPUT -d 100.64.0.0/10 -j DROP
iptables -A INPUT -d 169.254.0.0/16 -j DROP
iptables -A INPUT -d 192.0.0.0/24 -j DROP
iptables -A INPUT -d 192.0.2.0/24 -j DROP
iptables -A INPUT -d 198.18.0.0/15 -j DROP
iptables -A INPUT -d 198.51.100.0/24 -j DROP
iptables -A INPUT -d 203.0.113.0/24 -j DROP
iptables -A INPUT -d 224.0.0.0/3 -j DROP
iptables -A INPUT -i lo -j ACCEPT

echo "Gathering Information..."
hardinfo -r -f html 
chkrootkit 
lynis -c 
freshclam
clamscan -r /
service --status-all
read -p "Press enter key when done..."

echo "Please check repo for issues..."
nano /etc/apt/sources.list
gpg /etc/apt/trusted.gpg > /tmp/trustedGPG
echo "Please check /tmp/trustedGPG for trusted GPG keys..."

echo "Answer With yes Or no. If You Are Not Sure Put skip"
echo "Does this machine need Samba?"
read sambaYN
echo "Does this machine need FTP?"
read ftpYN
echo "Does this machine need SSH?"
read sshYN
echo "Does this machine need Telnet?"
read telnetYN
echo "Does this machine need Mail?"
read mailYN
echo "Does this machine need Printing?"
read printYN
echo "Does this machine need MySQL?"
read dbYN
echo "Will this machine be a Web Server?"
read httpYN
echo "Does this machine need DNS?"
read dnsYN
echo "Does this machine allow media files?"
read mediaFilesYN

echo "Dealing with Samba..."
if [ $sambaYN == no ]
then
	apt-get purge samba -y -qq
	apt-get purge samba-common -y  -qq
	apt-get purge samba-common-bin -y -qq
	apt-get purge samba4 -y -qq
	echo "Samba has been removed."
elif [ $sambaYN == yes ]
then
	echo "Create seperate passwords for each user"
	cp /etc/samba/smb.conf ~/Desktop/backups/
	gedit /etc/samba/smb.conf
fi
echo "Samba is complete"

echo "Dealing with FTP..."
if [ $ftpYN == no ]
then
	ufw deny ftp 
	ufw deny sftp 
	ufw deny saft 
	ufw deny ftps-data 
	ufw deny ftps
	apt-get purge vsftpd -y -qq
	ecjo "VsFTPd has been removed. FTP, SFTP, SAFT, FTPS-Data, and FTPS ports have been denied"
elif [ $ftpYN == yes ]
then
	ufw allow ftp 
	ufw allow sftp 
	ufw allow saft 
	ufw allow ftps-data 
	ufw allow ftps
	cp /etc/vsftpd/vsftpd.conf ~/Desktop/backups/
	cp /etc/vsftpd.conf ~/Desktop/backups/
	gedit /etc/vsftpd/vsftpd.conf&gedit /etc/vsftpd.conf
	service vsftpd restart
	echo "FTP, SFTP, SAFT, FTPS-Data, and FTPS ports have been allowed. VsFTPd has been started."
fi
echo "FTP is complete."

echo "Dealing with SSH..."
if [ $sshYN == no ]
then
	ufw deny ssh
	apt-get purge openssh-server -y -qq
	echo "Open-SSH has been removed. SSH port has been denied."
elif [ $sshYN == yes ]
then
	ufw allow ssh
	cp /etc/ssh/sshd_config ~/Desktop/backups/	
	grep PermitRootLogin /etc/ssh/sshd_config | grep yes
	if [ $?==0 ]
	then
  	  sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
	  sed -i 's/PermitRootLogin without-password/PermitRootLogin no/g' /etc/ssh/sshd_config

	fi
	grep Protocol /etc/ssh/sshd_config | grep 1
	if [ $?==0 ]
	then
	  sed -i 's/Protocol 2,1/Protocol 2/g' /etc/ssh/sshd_config
	  sed -i 's/Protocol 1,2/Protocol 2/g' /etc/ssh/sshd_config
	fi
	grep X11Forwarding /etc/ssh/sshd_config | grep yes
	if [ $?==0 ]
	then
	  sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
	fi
	grep PermitEmptyPasswords /etc/ssh/sshd_config | grep yes
	if [ $?==0 ]
	then
	  sed -i 's/PermitEmptyPasswords yes/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
	fi
	service ssh restart
	echo "SSH port has been allowed on the firewall. SSH config file has been configured."
fi
echo "SSH is complete."

echo "Dealing with Telnet..."
if [ $telnetYN == no ]
then
	ufw deny telnet 
	ufw deny rtelnet 
	ufw deny telnets
	apt-get purge telnet -y -qq
	apt-get purge telnetd -y -qq
	apt-get inetutils-telnetd -y -qq
	apt-get telnetd-ssl -y -qq
	echo "Telnet has been removed. Telnet port has been denied."
elif [ $telnetYN == yes ]
then
	ufw allow telnet 
	ufw allow rtelnet 
	ufw allow telnets
	echo "Telnet port has been allowed."
fi
echo "Telnet is complete."

echo "Dealing with mail..."
if [ $mailYN == no ]
then
	ufw deny smtp 
	ufw deny pop2 
	ufw deny pop3
	ufw deny imap2 
	ufw deny imaps 
	ufw deny pop3s
	echo "SMTP, POP2, POP3, IMAP2, IMAPS, and POP3S ports have been denied."
elif [ $mailYN == yes ]
then
	ufw allow smtp 
	ufw allow pop2 
	ufw allow pop3
	ufw allow imap2 
	ufw allow imaps 
	ufw allow pop3s
	echo "SMTP, POP2, POP3, IMAP2, IMAPS, and POP3S ports have been allowed."
fi
echo "Mail is complete."

echo "Dealing with printing..."
if [ $printYN == no ]
then
	ufw deny ipp 
	ufw deny printer 
	ufw deny cups
	echo "IPP, Printer, and Cups ports have been denied."
elif [ $printYN == yes ]
then
	ufw allow ipp 
	ufw allow printer 
	ufw allow cups
	echo "IPP, Printer, and Cups ports have been allowed."
fi
echo "Printing is complete."

echo "Dealing with MySQL..."
if [ $dbYN == no ]
then
	ufw deny ms-sql-s 
	ufw deny ms-sql-m 
	ufw deny mysql 
	ufw deny mysql-proxy
	apt-get purge mysql -y -qq
	apt-get purge mysql-client-core-5.5 -y -qq
	apt-get purge mysql-server -y -qq
	apt-get purge mysql-server-5.5 -y -qq
	apt-get purge mysql-client-5.5 -y -qq
	echo " MySQL has been removed. MS-SQL-S, MS-SQL-M, MySQL, and MySQL-Proxy ports have been denied."
elif [ $dbYN == yes ]
then
	ufw allow ms-sql-s 
	ufw allow ms-sql-m 
	ufw allow mysql 
	ufw allow mysql-proxy
	cp /etc/my.cnf ~/Desktop/backups/
	cp /etc/mysql/my.cnf ~/Desktop/backups/
	cp /usr/etc/my.cnf ~/Desktop/backups/
	cp ~/.my.cnf ~/Desktop/backups/
	gedit /etc/my.cnf&gedit /etc/mysql/my.cnf&gedit /usr/etc/my.cnf&gedit ~/.my.cnf
	service mysql restart
	echo " MySQL service has been restarted. MS-SQL-S, MS-SQL-M, MySQL, and MySQL-Proxy ports have been allowed."
fi
echo "MySQL is complete."

echo "Dealing with Web Server..."
if [ $httpYN == no ]
then
	ufw deny http
	ufw deny https
	apt-get purge apache2 -y -qq
	rm -r /var/www/*
	echo "Apache2 has been removed. Web server files have been removed. HTTP and HTTPS ports have been denied."
elif [ $httpYN == yes ]
then
	ufw allow http 
	ufw allow https
	cp /etc/apache2/apache2.conf ~/Desktop/backups/
	if [ -e /etc/apache2/apache2.conf ]
	then
  	  echo -e '\<Directory \>\n\t AllowOverride None\n\t Order Deny,Allow\n\t Deny from all\n\<Directory \/\>\nUserDir disabled root' >> /etc/apache2/apache2.conf
	fi
	chown -R root:root /etc/apache2
	chown -R root:root /etc/apache
	echo "Apache2 config file has been configured. Only root can now access the Apache2 folder. HTTP and HTTPS ports have been allowed."
fi
echo "Web Server is complete."

echo "Dealing with DNS..."
if [ $dnsYN == no ]
then
	ufw deny domain
	apt-get purge bind9 -qq
	echo "DNS name binding has been removed. Domain port has been denied."
elif [ $dnsYN == yes ]
then
	ufw allow domain
	echo "Domain port has been allowed."
fi
echo "DNS is complete."

echo "Dealing with media files..."
if [ $mediaFilesYN == no ]
then
	find / -name "*.midi" -type f -delete
	find / -name "*.mid" -type f -delete
	find / -name "*.mod" -type f -delete
	find / -name "*.mp3" -type f -delete
	find / -name "*.mp2" -type f -delete
	find / -name "*.mpa" -type f -delete
	find / -name "*.abs" -type f -delete
	find / -name "*.mpega" -type f -delete
	find / -name "*.au" -type f -delete
	find / -name "*.snd" -type f -delete
	find / -name "*.wav" -type f -delete
	find / -name "*.aiff" -type f -delete
	find / -name "*.aif" -type f -delete
	find / -name "*.sid" -type f -delete
	find / -name "*.flac" -type f -delete
	find / -name "*.ogg" -type f -delete
	echo "Audio files removed..."
	find / -name "*.mpeg" -type f -delete
	find / -name "*.mpg" -type f -delete
	find / -name "*.mpe" -type f -delete
	find / -name "*.dl" -type f -delete
	find / -name "*.movie" -type f -delete
	find / -name "*.movi" -type f -delete
	find / -name "*.mv" -type f -delete
	find / -name "*.iff" -type f -delete
	find / -name "*.anim5" -type f -delete
	find / -name "*.anim3" -type f -delete
	find / -name "*.anim7" -type f -delete
	find / -name "*.avi" -type f -delete
	find / -name "*.vfw" -type f -delete
	find / -name "*.avx" -type f -delete
	find / -name "*.fli" -type f -delete
	find / -name "*.flc" -type f -delete
	find / -name "*.mov" -type f -delete
	find / -name "*.qt" -type f -delete
	find / -name "*.spl" -type f -delete
	find / -name "*.swf" -type f -delete
	find / -name "*.dcr" -type f -delete
	find / -name "*.dir" -type f -delete
	find / -name "*.dxr" -type f -delete
	find / -name "*.rpm" -type f -delete
	find / -name "*.rm" -type f -delete
	find / -name "*.smi" -type f -delete
	find / -name "*.ra" -type f -delete
	find / -name "*.ram" -type f -delete
	find / -name "*.rv" -type f -delete
	find / -name "*.wmv" -type f -delete
	find / -name "*.asf" -type f -delete
	find / -name "*.asx" -type f -delete
	find / -name "*.wma" -type f -delete
	find / -name "*.wax" -type f -delete
	find / -name "*.wmv" -type f -delete
	find / -name "*.wmx" -type f -delete
	find / -name "*.3gp" -type f -delete
	find / -name "*.mov" -type f -delete
	find / -name "*.mp4" -type f -delete
	find / -name "*.avi" -type f -delete
	find / -name "*.swf" -type f -delete
	find / -name "*.flv" -type f -delete
	find / -name "*.m4v" -type f -delete
	echo "Video files removed..."
	find /home -name "*.tiff" -type f -delete
	find /home -name "*.tif" -type f -delete
	find /home -name "*.rs" -type f -delete
	find /home -name "*.im1" -type f -delete
	find /home -name "*.gif" -type f -delete
	find /home -name "*.jpeg" -type f -delete
	find /home -name "*.jpg" -type f -delete
	find /home -name "*.jpe" -type f -delete
	find /home -name "*.png" -type f -delete
	find /home -name "*.rgb" -type f -delete
	find /home -name "*.xwd" -type f -delete
	find /home -name "*.xpm" -type f -delete
	find /home -name "*.ppm" -type f -delete
	find /home -name "*.pbm" -type f -delete
	find /home -name "*.pgm" -type f -delete
	find /home -name "*.pcx" -type f -delete
	find /home -name "*.ico" -type f -delete
	find /home -name "*.svg" -type f -delete
	find /home -name "*.svgz" -type f -delete
	echo "Image files removed..."
	echo "All media files removed."
elif [ $mediaFilesYN == yes ]
then
	echo "No media removed"
fi
echo "Media files are complete."

echo "Removing Netcat and all other instances..."
apt-get purge netcat -y -qq
apt-get purge netcat-openbsd -y -qq
apt-get purge netcat-traditional -y -qq
apt-get purge ncat -y -qq
apt-get purge pnetcat -y -qq
apt-get purge socat -y -qq
apt-get purge sock -y -qq
apt-get purge socket -y -qq
apt-get purge sbd -y -qq
rm /usr/bin/nc

echo "Removing John the Ripper..."
apt-get purge john -y -qq
apt-get purge john-data -y -qq

echo "Removing Hydra..."
apt-get purge hydra -y -qq
apt-get purge hydra-gtk -y -qq

echo "Removing Aircrack-NG..."
apt-get purge aircrack-ng -y -qq

echo "Removing FCrackZIP..."
apt-get purge fcrackzip -y -qq

echo "Removing LCrack..."
apt-get purge lcrack -y -qq

echo "Removing OphCrack..."
apt-get purge ophcrack -y -qq
apt-get purge ophcrack-cli -y -qq

echo "Removing PDFCrack..."
apt-get purge pdfcrack -y -qq

echo "Removing Pyrit..."
apt-get purge pyrit -y -qq

echo "Removing RARCrack..."
apt-get purge rarcrack -y -qq

echo "Removing SipCrack..."
apt-get purge sipcrack -y -qq

echo "Removing IRPAS..."
apt-get purge irpas -y -qq

echo "Removing Zeitgeist..."
apt-get purge zeitgeist-core -y -qq
apt-get purge zeitgeist-datahub -y -qq
apt-get purge python-zeitgeist -y -qq
apt-get purge rhythmbox-plugin-zeitgeist -y -qq
apt-get purge zeitgeist -y -qq

echo "Denying all outside packets from internet claiming to be from loopback..."
apt-get install iptables -y -qq
iptables -A INPUT -p all -s localhost  -i eth0 -j DROP

echo "Installing AppArmor..."
apt-get install apparmor apparmor-profiles -y -qq

echo "Backing up Crontab..."
crontab -l > ~/Desktop/backups/crontab-old
chmod 777 ~/Desktop/backups/crontab-old
crontab -r

echo "Only allowing root in Cron..."
cd /etc/
/bin/rm -f cron.deny at.deny
echo root >cron.allow
echo root >at.allow
/bin/chown root:root cron.allow at.allow
/bin/chmod 400 cron.allow at.allow
cd ..

echo "Removing all unused packages..."
apt-get autoremove -y -qq
apt-get autoclean -y -qq
apt-get clean -y -qq

echo "Enabling daily update checks, download upgradeable packages, autoclean interval, and unattended upgrades..."
chmod 777 /etc/apt/apt.conf.d/10periodic
cp /etc/apt/apt.conf.d/10periodic ~/Desktop/backups/
echo -e "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Download-Upgradeable-Packages \"1\";\nAPT::Periodic::AutocleanInterval \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";" > /etc/apt/apt.conf.d/10periodic
chmod 644 /etc/apt/apt.conf.d/10periodic

echo "Checking and getting updates for Ubuntu..."
apt-get update -qq
apt-get dist-upgrade -qq
echo "Turning on unatended updates..."
apt-get install unattended-upgrades -y 
dpkg-reconfigure -plow unattended-upgrades
vi /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Automatic-Reboot "true";
unattended-upgrades --dry-run

echo "Re-enabling root bash history..."
if [[ -L /root/.bash_history && ! $DRYRUN = true ]]; then
    unlink /root/.bash_history
    echo -n > /root/.bash_history
fi

echo "Checking for open ports..."
sudo netstat -tulpna
while (true)
do
    VAR10=0
    VAR11=""
    echo "What port do you want to close?"
    read VAR10
    sudo ufw deny VAR10
    echo "Do you want to close another port?"
    read VAR11
    if [ "$VAR11" != "Yes" ] || [ "$VAR11" != "yes" ]; then
        break
    fi
done

echo "Scanning for suspicious cron jobs..."
echo "Logging all user cronjobs..."
if [ "$(sudo ls -A /var/spool/cron/crontabs)" ] ; then
    echo "WARNING! User crontabs have been found!" >> log.txt
    sudo ls -A /var/spool/cron/crontabs >> log.txt
fi
echo "Printing out all root cron jobs..."
sudo cat /etc/crontab

echo "Fixing sources.list..."
VAR111=$(cat /etc/issue.net)
VAR112=$(echo $VAR111 | cut -c7-9)
VAR113=$(echo $VAR111 | cut -c1-6)
if [ $VAR113 -eq "Ubuntu" ]; then 
    if [ $VAR112 -eq "16" ]; then
        sudo cat ubu16.txt > /etc/apt/sources.list
    fi
    elif [ $VAR112 -eq "18" ]; then 
        sudo cat ubu18.txt > /etc/apt/sources.list
    fi
    elif [ $VAR112 -eq "20" ]; then
        sudo cat ubu20.txt > /etc/apt/sources.list
    fi
fi
elif [ $VAR113 -eq "Debian" ]; then
    sudo cat deb.txt > /etc/apt/sources.list
fi

echo "Clearing bash history..."
history -c
set +o history

echo "Fixing firefox settings..."
cd ~
cd ./.mozilla/firefox/*.default
touch user.js
function FirefoxPref() {
    echo "user_pref($1, $2);" | sudo tee -a user.js
}
FirefoxPref '"browser.safebrowsing.downloads.enabled"' "true"
FirefoxPref '"browser.safebrowsing.downloads.remote.enabled"' "true"
FirefoxPref '"browser.safebrowsing.downloads.remote.block_dangerous"' "true"
FirefoxPref '"browser.safebrowsing.downloads.remote.block_dangerous"' "true"
FirefoxPref '"browser.safebrowsing.downloads.remote.block_dangerous_host"' "true"
FirefoxPref '"browser.safebrowsing.downloads.remote.block_potentially_unwanted"' "true"
FirefoxPref '"browser.safebrowsing.downloads.remote.block_uncommon"' "true"
FirefoxPref '"browser.safebrowsing.malware.enabled"' "true"
FirefoxPref '"browser.safebrowsing.phishing.enabled"' "true"
FirefoxPref '"dom.disable_open_during_load"' "true"
FirefoxPref '"dom.block_multiple_popups"' "true"
FirefoxPref '"dom.block_download_insecure"' "true"
FirefoxPref '"dom.enable_performance"' "true"
FirefoxPref '"dom.allow_scripts_to_close_windows"' "false"
FirefoxPref '"media.autoplay.block-webaudio"' "true"
FirefoxPref '"media.block-autoplay-until-in-foreground"' "true"
FirefoxPref '"plugins.flashBlock.enabled"' "true"
FirefoxPref '"privacy.socialtracking.block_cookies.enabled"' "true"
FirefoxPref '"toolkit.telemetry.reportingpolicy.firstRun"' "false"
cd ~
echo "END"
