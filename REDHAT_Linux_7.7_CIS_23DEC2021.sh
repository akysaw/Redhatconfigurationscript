# Redhatconfigurationscript
#!/bin/bash

#THIS IS A CONFIG AUDIT TOOL FOR RHEL 7.7 Linux
#AUTHOR :: AKSHAY SAWANT
#DATE :: 23 DECEMBER 2021
#USAGE :: You need to run the script as root user
#REFERENCE DOCUMENT :: CIS Red Hat Enterprise Linux 7 Benchmark v3.1.1 - 05-21-2021 
#First do su root and then run the script
#Wont work with sudo

function start()
{

IP=$(ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/')
#CHECK FOLDER WITH SAME NAME EXISTS
if [[ -d $IP ]]
then
echo "DIRECTORY $IP already exists. Please Rename it first"
exit
else
mkdir $IP
fi


function prob()
{
RED='\033[0;31m'
echo -e "${RED}$1\e[0m"
}

function auditpoint()
{
GREEN='\033[0;32m'
echo -e "${GREEN}$1\e[0m\n\n"
}


function check()
{
BLUE='\033[0;36m'
echo -e "${BLUE}$1\e[0m"
}

clear
cat <<a
--------------------------------------------
echo " / ``\  | |  / / \ \   / /           "
echo "|_|_|_| | | / /    \\ //            "
echo "| ___ | | | /\      | |              "
echo "| | | | | | \ \     | |              "
echo "|_| |_|_| |  \_\,_  |_|              "
--------------------------------------------                                     

      REDHAT 7.7 Linux Configuration Audit Script
             -NETWORK TEAM


a
sleep 2
echo '-----------------------------------------------------------'
auditpoint "OS Version and details"
cat /etc/redhat-release
echo -e '\n\n'
hostnamectl
echo '-----------------------------------------------------------'
sleep 2
echo '-----------1.INITIAL_SETUP---------------------------------'
echo '-----------1.1_FILESYSTEM_CONFIGURATION--------------------'

prob "Checking Unused FileSystems"
auditpoint "Ensure mounting of cramfs filesystems is disabled"
modprobe -n -v cramfs | grep -E '(cramfs|install)'
check "check if 'install /bin/true' is returned."
echo -e '\n\n'
lsmod | grep cramfs
check "check if no output is returned."
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint " Ensure mounting of squashfs filesystems is disabled"
modprobe -n -v squashfs | grep -E '(squashfs|install)'
check "check if 'install /bin/true' is returned."
echo -e '\n\n'
lsmod | grep squashfs
check "check if no output is returned."
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint " Ensure mounting of udf filesystems is disabled"
modprobe -n -v udf | grep -E '(udf|install)'
check "check if 'install /bin/true' is returned."
echo -e '\n\n'
lsmod | grep udf
check "check that no output should return."
echo -e '\n\n'
echo '-----------------------------------------------------------'
sleep 2

prob "Checking /tmp Configuration"
auditpoint "Ensure /tmp is configured"
findmnt -n /tmp
check "check if '/tmp tmpfs tmpfs rw,nosuid,nodev,noexec' is returned."
echo -e '\n\n'
grep -E '\s/tmp\s' /etc/fstab | grep -E -v '^\s*#'
check "check if 'tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0c' is returned."
echo -e '\n\n'
systemctl show "tmp.mount" | grep -i unitfilestate
check "check if 'UnitFileState=enabled' is returned."
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint " Ensure noexec option set on /tmp partition"
findmnt -n /tmp | grep -Ev '\bnodev\b'
check "check that no output should return"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "  Ensure nodev option set on /tmp partition"
findmnt -n /tmp -n | grep -Ev '\bnodev\b'
check "check that no output should return"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "  Ensure nosuid option set on /tmp partition"
findmnt -n /tmp -n | grep -Ev '\bnosuid\b'
check "check that no output should return"
echo -e '\n\n'
echo '-----------------------------------------------------------'

sleep 2
prob "Checking /dev/shm  Configuration"
auditpoint "  Ensure /dev/shm is configured"
findmnt -n /dev/shm
check "check that 'tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime,seclabel)' should return"
grep -E '\s/dev/shm\s' /etc/fstab
check "check that 'tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid 0 0' should return"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint " Ensure noexec option set on /dev/shm partition"
findmnt -n /dev/shm | grep -Ev '\bnoexec\b'
check "check that no should return"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure nodev option set on /dev/shm partition"
findmnt -n /dev/shm | grep -Ev '\bnodev\b'
check "check that no should return"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure nosuid option set on /dev/shm partition"
findmnt -n /dev/shm | grep -Ev '\bnosuid\b'
check "check that no should return"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure separate partition exists for /var"
findmnt /var
check "check output returned"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure separate partition exists for /var/tmp"
findmnt /var/tmp
check "check output returned"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure /var/tmp partition includes the noexec option"
findmnt -n /var/tmp | grep -Ev '\bnoexec\b'
check "check that no output should returned"
echo -e '\n\n'
echo '-----------------------------------------------------------'


auditpoint "Ensure /home partition includes the nodev option"
findmnt /home | grep -Ev '\bnodev\b'
check "check that no output should returned"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure sticky bit is set on all world-writable directories  "
df --local -P 2> /dev/null | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
check "check that no output should returned"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint " Disable Automounting"
systemctl show "autofs.service" | grep -i unitfilestate=enabled
check "check that no output should returned"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Disable USB Storage"
modprobe -n -v usb-storage
check "check that 'install /bin/true' returned"
lsmod | grep usb-storage
check "check that no output should returned"
echo -e '\n\n'
echo '-----------------------------------------------------------'
sleep2

echo '-----------SOFTWARE_UPDATES--------------------------------'
auditpoint "Ensure GPG keys are configured"
rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'
check "check output returned"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure package manager repositories are configured"
yum repolist
check "check output returned"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure gpgcheck is globally activated "
grep ^\s*gpgcheck /etc/yum.conf
check "check that 'gpgcheck=1' returned"
echo -e '\n\n'
grep -P '^\h*gpgcheck=[^1\n\r]+\b(\h+.*)?$' /etc/yum.conf
/etc/yum.repos.d/*.repo
check "check that no output should returned"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint"Ensure Red Hat Subscription Manager connection is configured "
subscription-manager identity
check "check output returned"
echo -e '\n\n'
echo '-----------------------------------------------------------'


auditpoint"Ensure AIDE is installed"
rpm -q aide
check "check aide version"
echo -e '\n\n'
echo '-----------------------------------------------------------'

echo '-----------BOOT SETTINGS-----------------------------------'

auditpoint"Ensure authentication required for single user mode"
grep /sbin/sulogin /usr/lib/systemd/system/rescue.service
check "check output returned"
echo -e '\n\n'
echo '-----------------------------------------------------------'
grep /sbin/sulogin /usr/lib/systemd/system/emergency.service
check "check output returned"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint"Ensure core dumps are restricted"
grep -E "^\s*\*\s+hard\s+core" /etc/security/limits.conf /etc/security/limits.d/*
check "check output returned"
echo -e '\n\n'
sysctl fs.suid_dumpable
check "check output returned should be 0"
echo -e '\n\n'
grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*
check "check output returned should be 0"
echo -e '\n\n'
echo '-----------------------------------------------------------'

echo '-----------SELINUX ----------------------------------------'
auditpoint"Ensure SELinux is installed"
rpm -q libselinux
check "check libselinux version"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint"Ensure SELinux policy is configured"
grep SELINUXTYPE= /etc/selinux/config
check "check ouput id 'targeted'"
echo -e '\n\n'
sestatus | grep 'Loaded policy'
check "check output returned"
echo -e '\n\n'
echo '-----------------------------------------------------------'
sleep2
echo '-----------COMMANDLINE WARNING BANNERS---------------------'
auditpoint"Ensure message of the day is configured properly"
cat /etc/motd
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint"Ensure local login warning banner is configured properly"
cat /etc/issue
echo -e '\n\n'
echo '-----------------------------------------------------------'


auditpoint "Ensure remote login warning banner is configured properly"
cat /etc/issue.net
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure permissions on /etc/issue are configured"
stat /etc/issue.net
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint " Ensure XDCMP is not enabled"
grep -Eis '^\s*Enable\s*=\s*true' /etc/gdm/custom.conf
check "check ouput is not returned"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure updates, patches, and additional security software are installed"
yum check-update
echo -e '\n\n'
echo '-----------------------------------------------------------'

echo '-----------inetd Services----------------------------------'
auditpoint "  Ensure xinetd is not installed"
rpm -q xinetd
check "check package xinetd is not installed"
echo -e '\n\n'
echo '-----------------------------------------------------------'


echo '-----------Special Purpose Services------------------------'
auditpoint " Ensure time synchronization is in use  "
rpm -q chrony ntp
check "check chrony version"
rpm -q ntp
check "check ntp version"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint " Ensure chrony is configured  "
grep -E "^(server|pool)" /etc/chrony.conf
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'


auditpoint " Ensure ntp is configured  "
systemctl is-enabled ntpd
check "check if enabled or disabled"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure X11 Server components are not installed"
rpm -qa xorg-x11-server*
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure Avahi Server are not installed"
rpm -q avahi-autoipd avahi
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure CUPS is not installed"
rpm -q cups
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure DHCP Server is not installed"
rpm -q dhcp
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure LDAP server is not installed"
rpm -q openldap-servers
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure DNS Server is not installed"
rpm -q bind
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure FTP Server is not installed"
rpm -q vsftpd
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure HTTP server is not installed "
rpm -q httpd
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure IMAP and POP3 server is not installed"
rpm -q dovecot
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure Samba is not installed"
rpm -q samba
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure HTTP Proxy Server is not installed"
rpm -q squid
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure net-snmp is not installed"
rpm -q net-snmp
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure NIS server is not installed"
rpm -q ypserv
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure telnet-server is not installed"
rpm -q telnet-server
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure nfs-utils is not installed or the nfs-server service is masked "
rpm -q nfs-utils
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure rpcbind is not installed or the rpcbind services are masked "
rpm -q rpcbind
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'


echo '-----------Service Clients---------------------------------'

auditpoint "Ensure NIS Client is not installed "
rpm -q ypbind
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure rsh client is not installed "
rpm -q rsh
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure talk client is not installed "
rpm -q talk
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure telnet client is not installed "
rpm -q telnet
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure LDAP client is not installed "
rpm -q openldap-clients
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

echo '-----------NETWORK CONFIGURATION---------------------------'

auditpoint "Ensure IP forwarding is disabled"
sysctl net.ipv4.ip_forward
check "check output is 0"
grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf
/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
check "check that no output should return"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure packet redirect sending is disabled"
sysctl net.ipv4.conf.all.send_redirects
check "check output is 0"
sysctl net.ipv4.conf.default.send_redirects
check "check output is 0"
grep "net\.ipv4\.conf\.all\.send_redirects" /etc/sysctl.conf
/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
check "check output is 0"
grep "net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf
/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
check "check output is 0"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure source routed packets are not accepted"
sysctl net.ipv4.conf.all.accept_source_route
check "check output is 0"
sysctl net.ipv4.conf.default.accept_source_route
check "check output is 0"
grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf
/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
check "check output is 0"
grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf
/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
check "check output is 0"
echo -e '\n\n'
echo '-----------------------------------------------------------'


auditpoint "Ensure ICMP redirects are not accepted"
sysctl net.ipv4.conf.all.accept_redirects
check "check output is 0"
sysctl net.ipv4.conf.default.accept_redirects
check "check output is 0"
grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf
/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
check "check output is 0"
grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf
/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
check "check output is 0"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure secure ICMP redirects are not accepted "
sysctl net.ipv4.conf.all.secure_redirects
check "check output is 0"
sysctl net.ipv4.conf.default.secure_redirects
check "check output is 0"
grep "net\.ipv4\.conf\.all\.secure_redirects" /etc/sysctl.conf
/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
check "check output is 0"
grep "net\.ipv4\.conf\.default\.secure_redirects" /etc/sysctl.conf
/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
check "check output is 0"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure suspicious packets are logged "
sysctl net.ipv4.conf.all.log_martians
check "check output is 1"
sysctl net.ipv4.conf.default.log_martians
check "check output is 1"
grep "net\.ipv4\.conf\.all\.log_martians" /etc/sysctl.conf
/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
check "check output is 1"
grep "net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf
/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
check "check output is 1"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure broadcast ICMP requests are ignored "
sysctl net.ipv4.icmp_echo_ignore_broadcasts
check "check output is 1"
grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf
/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
check "check output is 1"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure bogus ICMP responses are ignored"
sysctl net.ipv4.icmp_ignore_bogus_error_responses
check "check output is 1"
 grep "net.ipv4.icmp_ignore_bogus_error_responses" /etc/sysctl.conf
/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
check "check output is 1"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure Reverse Path Filtering is enabled"
sysctl net.ipv4.conf.all.rp_filter
check "check output is 1"
sysctl net.ipv4.conf.default.rp_filter
check "check output is 1"
grep "net\.ipv4\.conf\.all\.rp_filter" /etc/sysctl.conf
/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
check "check output is 1"
grep "net\.ipv4\.conf\.default\.rp_filter" /etc/sysctl.conf
/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
check "check output is 1"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure TCP SYN Cookies is enabled"
sysctl net.ipv4.tcp_syncookies
check "check output is 1"
grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
check "check output is 1"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure IPv6 router advertisements are not accepted"
sysctl net.ipv6.conf.all.accept_ra
check "check output is 0"
sysctl net.ipv6.conf.default.accept_ra
check "check output is 0"
grep "net\.ipv6\.conf\.all\.accept_ra" /etc/sysctl.conf
/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
check "check output is 0"
grep "net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf
/etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
check "check output is 0"
echo -e '\n\n'
echo '-----------------------------------------------------------'


auditpoint "Ensure DCCP is disabled"
modprobe -n -v dccp
check "check for output  'install /bin/true' "
lsmod | grep dccp
check "check that no output should be returned"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure SCTP is disabled"
modprobe -n -v sctp
check "check for output  'install /bin/true' "
lsmod | grep sctp
check "check that no output should be returned"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure firewalld is installed"
rpm -q firewalld iptables
check "check firewall and iptables version"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint " Ensure iptables-services not installed with firewalld"
rpm -q iptables-service
check "check if service package is not installed"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure nftables either not installed or masked with firewalld"
rpm -q nftables
check "check if package is not installed"
systemctl is-enabled nftables
check "check if output is 'masked'"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure firewalld service enabled and running"
systemctl is-enabled firewalld
check "check if it is enabled"
firewall-cmd --state
check "check if it is in running state"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure iptables packages are installed"
rpm -q iptables iptables-services
check "check version"
echo -e '\n\n'
echo '-----------------------------------------------------------'


auditpoint " Ensure iptables is enabled and running"
systemctl is-enabled iptables
check "check if it is enabled"
echo -e '\n\n'
echo '-----------------------------------------------------------'

echo '-----------Logging and Auditing----------------------------'

auditpoint "Ensure auditd is installed"
rpm -q audit audit-libs
check " check version and verify if it is installed"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure auditd service is enabled and running"
systemctl is-enabled auditd
check "check if it is enabled"
systemctl status auditd | grep 'Active: active (running) '
check " check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure audit log storage size is configured" 
grep max_log_file /etc/audit/auditd.conf
check "check max_log_file size and verify with policy"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure audit logs are not automatically deleted"
grep max_log_file_action /etc/audit/auditd.conf
check "check max_log_file_action = keep_logs "
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint " Ensure rsyslog is installed"
rpm -q rsyslog
check "check version"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure rsyslog Service is enabled and running"
systemctl is-enabled rsyslog
check "check if it is enabled"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoints "Ensure permissions on all logfiles are configured"
find /var/log -type f -perm /g+wx,o+rwx -exec ls -l {} \;
check "check that no output should be returned"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "ensure sudo is installed"
rpm -q sudo
check "check version"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure sudo commands use pty"
grep -Ei '^\s*Defaults\s+([^#]\S+,\s*)?use_pty\b' /etc/sudoers
/etc/sudoers.d/*
check "check output is 'Defaults use_pty'"
echo -e '\n\n'
echo '-----------------------------------------------------------'


echo '------------SSH_configurations-----------------------------'

auditpoint " Ensure permissions on /etc/ssh/sshd_config are configured "
stat /etc/ssh/sshd_config
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure permissions on SSH private host key files are configured"
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \;
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure permissions on SSH public host key files are configured"
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \;
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

echo '-----Saving-----SSHD_CONFIG--------------------------------'
if [[ -e /etc/ssh/sshd_config ]]
then
blue "SSHD_CONFIG FILE SAVED"
echo ''
cp /etc/ssh/sshd_config sD-SSH_CONFIG
else
echo "ssh config files"
fi
echo '-----------------------------------------------------------'


echo '-----------------------------------------------------------'

echo '------------PASSWORD---------------------------------------'
auditpoint "Ensure password creation requirements are configured"
grep '^\s*minlen\s*' /etc/security/pwquality.conf
check "verify the minimum password length is 14 or more
characters."
grep '^\s*minclass\s*' /etc/security/pwquality.conf
check "verify the required password complexity is minclass = 4"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure lockout for failed password attempts is configured "
grep -E '^\s*auth\s+\S+\s+pam_(faillock|unix)\.so' /etc/pam.d/system-auth
/etc/pam.d/password-auth
check "check output and verify"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure password hashing algorithm is SHA-512 "
grep -P
'^\h*password\h+(sufficient|requisite|required)\h+pam_unix\.so\h+([^#\n\r]+)?
sha512(\h+.*)?$' /etc/pam.d/system-auth /etc/pam.d/password-auth
check "verify the sha512 option is included"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure password reuse is limited"
grep -P
'^\s*password\s+(requisite|required)\s+pam_pwhistory\.so\s+([^#]+\s+)*remembe
r=([5-9]|[1-9][0-9]+)\b' /etc/pam.d/system-auth /etc/pam.d/password-auth
check "Verify remembered password history follows local site policy, not to be less than 5."
grep -P
'^\s*password\s+(sufficient|requisite|required)\s+pam_unix\.so\s+([^#]+\s+)*r
emember=([5-9]|[1-9][0-9]+)\b' /etc/pam.d/system-auth /etc/pam.d/passwordauth
check "Verify remembered password history follows local site policy, not to be less than 5."
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure password expiration is 365 days or less"
grep ^\s*PASS_MAX_DAYS /etc/login.defs
check "verify the output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure default group for the root account is GID 0"
grep "^root:" /etc/passwd | cut -f4 -d:
check "verify the result is 0 "
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure root login is restricted to system console"
cat /etc/securetty
check "check output"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure permissions on /etc/passwd are configured"
stat /etc/passwd
check "verify Uid and Gid are both 0/root and Access is 644 or
more restrictive"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure permissions on /etc/passwd- are configured"
stat /etc/passwd-
check "verify Uid and Gid are both 0/root and Access is 644 or
more restrictive"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure permissions on /etc/shadow are configured"
stat /etc/shadow
check "verify Uid and Gid are 0/root , and Access is 0000"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure permissions on /etc/gshadow- are configured"
stat /etc/gshadow-
check "verify Uid is 0/root, Gid is 0/root and Access is
0000 "
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure permissions on /etc/group are configured"
stat /etc/group
check "verify Uid and Gid are both 0/root and Access is 644 or
more restrictive"
echo -e '\n\n'
echo '-----------------------------------------------------------'

auditpoint "Ensure root is the only UID 0 account"
awk -F: '($3 == 0) { print $1 }' /etc/passwd
check "verify that only 'root' is returned"
echo -e '\n\n'
echo '-----------------------------------------------------------'
echo '-----------------------------------------------------------'

mv sD-* $IP

}

if [ "$EUID" != 0 ]
then
echo "Run the script by su root"
exit
else
start
fi
