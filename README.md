# 2022 CYPAT SCRIPTS
### ONLY FOR USE BY CYPAT TEAM 15-4209
### CC BY-NC-ND
The .bat files are batch files for securing the windows and windows server images in the CyberPatriot
competion. They automatically secure many parts of windows and windows server images and will prompt for you to do 
some things manually. 

The .sh files are bash files for Ubuntu images in the CyberPatriot compition. They automatically secure many parts
of the Ubuntu image and will prompt for you to do some things manually. 

There are .txt versions of all files for editing/trouble-shooting.

These files scripts are only allowed to be used in the CyPat competition by CyPat team 15-4209 in my grade 9 year (2022) and can be used beyond that by only
CyberKiloCharlie. These scripts can be used for securing your own systems, so long as it is not a system in the CyPat competition. You can distribute the scripts so 
long as I (CyberKiloCharlie) am attributed as the author, and the distribution is not commercial in any form. Any use in the CyPat competion other than by team 15-4209
or by CyberKiloCharlie is not allowed under section 3011-1-d and 3011.4.5.b of the CyPat XV national youth cyber defense competition rule book and is punishable by
disqualification from the CyPat tournament. 

# How to run scripts;
### Linux (Ubuntu);
```
sudo apt install git
git clone https://github.com/cyberkilocharlie/cmdtools.git
cd cmdtools
ls
sudo sh [ENTER SCRIPT NAME HERE].sh
```
### Windows;
```
Go to https://github.com/cyberkilocharlie/cmdtools
Download Files
Find file in File Explorer (Downloads)
Unzip File
Enter Unziped File
Find the .bat file you want to run 
Right click that file
Click Run as Administrator
```
# Quick overview of the scripts;
(All operations are in order)
### WINDOWS BATCH 1;
```
Checks if script is running as admin
Deals with remote desktop
Starts firewall 
Sets firewall rules
Disables guest accounts
Configures ports
Removes saved credentials
Starts/stops services
Checks disk
Disables services
Enables auditing
Sets Do Not Display Last User On Logon
Disables Domain Credential Storage
Unallows Remote Access To Floppies
Sets Idle Time Limit To 45 Minutes
Configures firewall settings
Disables shutdown without logon
Deals with password policy settings
Turns on auto updates
Updates windows
Restarts windows
```
### WINDOWS BATCH 2;
```
Deals with MalwareBytes
Lists Users
Prompts you to fix UAC settings
Lists tasks
Gets Windows Defender Stats
Runs Windows Defender Scan
Opens Windows Defender
Turns firewall on (again)
Lists Networks
Opens Windows Defender Security Center
Deals with unallowed media
Manages registry keys
Restricts CD ROM drive
Disables auto Admin logon
Clears page file
Prevents users from installing printer drivers
Enables LSA protection
Limits use of blank passwords
Audits access of Global System Objects
Audits Backup and Restore
Restricts Anonymous Enumeration
Disables storage of domain passwords
Takes away Anonymous user Everyone permissions
Allows Machine ID for NTLM
Enables do not display last user on logon
Enables Installer Detection
Disables undocking without logon
Enables CTRL+ALT+DEL
Disables machine account password changes
Requires strong session key
Requires Sign/Seal
Signs Channel
Seals Channel
Requires Security Signature - Disabled pursuant to checklist
Cleares null session pipes
Disables IE password caching
Warns users if website has a bad certificate
Warns users if website redirects
Enables Do Not Track
Shows hidden files
Disables sticky keys
Shows super hidden files
Disables dump file creation
Disables autoruns
Lists Possible Penetrations
Prompts you to Enable Password Policy: Password Policy Must Meet Complexity
Prompts you to Disable Password Policy: Store Passwords Using Reversible Encryption
Prompts you to Enable CTRL ALT DEL At Logon
Lists Networks (Again)
Prompts you to find Unwanted Media Files using Wild Card Searches
Prompts you to Delete Unnecesary Programs
Flashes Disk to .flashed Files
Finds Hacktools
Runs System Integrety Check
Runs MRT
```
### UBUNTU BASH 1;
```
Checks os type
Checks for root privileges
Installs good programs
Deals with users
Removes alias
Locks root account
Sets bash history file permissions
Sets Read/Write permissions on shadow
Updates shadow password configuration file
Updates PAM authentication file
Updates PAM password file
Removes GNOME games
Lists files in user directories
Removes games from /usr/
Removes unneeded software
Disables unneeded services
Restricts compiler access
Sets shadow file permissions
Sets account file permission
Sets group file permissions
Sets PAM file permissions
Sets group password file permissions
Sets Cron file permissions
Disables core dumps
Sets hosts file to defaults
Secures LightDM
Removes scripts in bin
Backs Up This Machine
Backs up /etc/group And /etc/passwd Files 
Installs Program Updates
Secures Network
Backs up IPTables
Clears out IPTables
Blocks Bogons
Gathers Information
Prompts you to check repo for issues
Deals with vunreble programs/services
Removes Netcat and all other instances
Removes hacking tools
Denys all outside packets from internet claiming to be from loopback
Backs up Crontab
Allows only root in Cron
Enables daily update checks, download upgradeable packages, autoclean interval, and unattended upgrades
Checks and gets updates for Ubuntu
Removes all unused packages
Checks for open ports
Deals with ports
Scans for suspicious cron jobs
Prints all root cron jobs
Fixs sources.list
Clears bash history
Fixes firefox settings
```
-CyberKiloCharlie
