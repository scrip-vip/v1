bash
#!/bin/bash

# Color variables
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'

# Clear screen
clear

# Exporting IP Address Information
export IP=$(curl -sS icanhazip.com)

# Clear data
clear && clear && clear
clear;clear;clear

# Banner
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo -e "  Welcome To B-Liv TUNNELING SCRIPT ${YELLOW}(${NC}${green} Stable Edition ${NC}${YELLOW})${NC}"
echo -e " This Will Quick Setup VPN Server On Your Server"
echo -e "  Author : ${green}B-Liv TUNNELING ® ${NC}${YELLOW}(${NC} ${green} YANG NYOLONG YATIM ${NC}${YELLOW})${NC}"
echo -e " © Recode By My Self B-Liv TUNNELING ${YELLOW}(${NC} 2023 ${YELLOW})${NC}"
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo ""
sleep 2

# Checking Os Architecture
if [[ $(uname -m | awk '{print $1}') == "x86_64" ]]; then
    echo -e "${OK} Your Architecture Is Supported ( ${green}$(uname -m)${NC} )"
else
    echo -e "${ERROR} Your Architecture Is Not Supported ( ${YELLOW}$(uname -m)${NC} )"
    exit 1
fi

# Checking System
if [[ $(grep -w ID /etc/os-release | head -n1 | sed 's/.*=//g') == "ubuntu" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$(grep -w PRETTY_NAME /etc/os-release | head -n1 | sed 's/.*=//g' | sed 's/"//g')${NC} )"
elif [[ $(grep -w ID /etc/os-release | head -n1 | sed 's/.*=//g') == "debian" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$(grep -w PRETTY_NAME /etc/os-release | head -n1 | sed 's/.*=//g' | sed 's/"//g')${NC} )"
else
    echo -e "${ERROR} Your OS Is Not Supported ( ${YELLOW}$(grep -w PRETTY_NAME /etc/os-release | head -n1 | sed 's/.*=//g' | sed 's/"//g')${NC} )"
    exit 1
fi

# IP Address Validating
if [[ $IP == "" ]]; then
    echo -e "${ERROR} IP Address ( ${YELLOW}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

# Validate Successful
echo ""
read -p "$( echo -e "Press ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} For Starting Installation")" ""
echo ""
clear

# Check if script is running as root
if [ "${EUID}" -ne 0 ]; then
    echo "You need to run this script as root"
    exit 1
fi

# Check if system is OpenVZ
if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ is not supported"
    exit 1
fi

# Repository
REPO="https://raw.githubusercontent.com/gotza02/v1/main/"

####
start=$(date +%s)
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

### Status
function print_ok() {
    echo -e "${OK} ${BLUE} $1 ${FONT}"
}
function print_install() {
    echo -e "${green} =============================== ${FONT}"
    echo -e "${YELLOW} # $1 ${FONT}"
    echo -e "${green} =============================== ${FONT}"
    sleep 1
}

function print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}

function print_success() {
    if [[ 0 -eq $? ]]; then
        echo -e "${green} =============================== ${FONT}"
        echo -e "${Green} # $1 berhasil dipasang"
        echo -e "${green} =============================== ${FONT}"
        sleep 2
    fi
}

# Create Xray directories
print_install "Creating Xray directories"
mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain
mkdir -p /var/log/xray
chown www-data.www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
mkdir -p /var/lib/kyt >/dev/null 2>&1

# RAM usage calculations
while IFS=":" read -r a b; do
    case $a in
        "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
        "Shmem") ((mem_used+=${b/kB}))  ;;
        "MemFree" | "Buffers" | "Cached" | "SReclaimable")
        mem_used="$((mem_used-=${b/kB}))"
    ;;
    esac
done < /proc/meminfo

Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"
export tanggal=$(date -d "0 days" +"%d-%m-%Y - %X")
export OS_Name=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | sed 's/.*=//g' | sed 's/"//g')
export Kernel=$(uname -r)
export Arch=$(uname -m)
export IP=$(curl -s https://ipinfo.io/ip/)

# Change Environment System
function first_setup() {
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Directory Xray"

    if [[ $(grep -w ID /etc/os-release | head -n1 | sed 's/.*=//g') == "ubuntu" ]]; then
        echo "Setup Dependencies $(grep -w PRETTY_NAME /etc/os-release | head -n1 | sed 's/.*=//g' | sed 's/"//g')"
        sudo apt update -y
        apt-get install --no-install-recommends software-properties-common -y
        add-apt-repository ppa:vbernat/haproxy-2.7 -y
        apt-get update -y
        apt-get install haproxy=2.7.\* -y
    elif [[ $(grep -w ID /etc/os-release | head -n1 | sed 's/.*=//g') == "debian" ]]; then
        echo "Setup Dependencies for OS $(grep -w PRETTY_NAME /etc/os-release | head -n1 | sed 's/.*=//g' | sed 's/"//g')"
        apt install gnupg2 curl lsb-release -y
        curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor > /usr/share/keyrings/haproxy.debian.net.gpg
        echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" http://haproxy.debian.net $(lsb_release -cs)-backports-2.7 main > /etc/apt/sources.list.d/haproxy.list
        apt update -y
        apt install haproxy=2.7.\* -y
    else
        echo -e " Your OS Is Not Supported ($(grep -w PRETTY_NAME /etc/os-release | head -n1 | sed 's/.*=//g' | sed 's/"//g'))"
        exit 1
    fi
}

# Install Nginx
function nginx_install() {
    if [[ $(grep -w ID /etc/os-release | head -n1 | sed 's/.*=//g') == "ubuntu" ]]; then
        print_install "Setup Nginx for $(grep -w PRETTY_NAME /etc/os-release | head -n1 | sed 's/.*=//g' | sed 's/"//g')"
        sudo apt install nginx -y
    elif [[ $(grep -w ID /etc/os-release | head -n1 | sed 's/.*=//g') == "debian" ]]; then
        print_success "Setup Nginx for $(grep -w PRE

TTY_NAME /etc/os-release | head -n1 | sed 's/.*=//g' | sed 's/"//g')"
        apt install nginx -y
    else
        echo -e " Your OS Is Not Supported ( ${YELLOW}$(grep -w PRETTY_NAME /etc/os-release | head -n1 | sed 's/.*=//g' | sed 's/"//g')${FONT} )"
        exit 1
    fi
}

# Update and remove packages
function base_package() {
    clear
    print_install "Installing Required Packages"
    apt install zip pwgen openssl netcat curl socat cron bash-completion -y
    apt install figlet jq -y
    apt update -y
    apt upgrade -y
    apt dist-upgrade -y
    apt autoremove --purge -y
    apt clean all

    systemctl enable chronyd
    systemctl restart chronyd
    systemctl enable chrony
    systemctl restart chrony
    chronyc sourcestats -v
    chronyc tracking -v
    apt install ntpdate -y
    ntpdate pool.ntp.org
    apt install sudo -y
    apt install ruby -y
    gem install lolcat

    apt install gnupg gnupg2 gnupg1 -y
    apt-get clean all
    apt-get autoremove -y
    apt-get install -y debconf-utils
    apt-get remove --purge exim4 -y
    apt-get remove --purge ufw firewalld -y
    apt-get install -y --no-install-recommends software-properties-common

    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    apt install -y speedtest-cli vnstat iptables iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 ca-certificates lsb-release fail2ban

    print_success "Required Packages Installed"
}

# Function to input domain
function pasang_domain() {
    clear
    echo -e "   .----------------------------------."
    echo -e "   |\e[1;32mPlease choose a domain type below\e[0m|"
    echo -e "   '----------------------------------'"
    echo -e "     \e[1;32m1)\e[0m Use your own domain"
    echo -e "     \e[1;32m2)\e[0m Use automatic domain pointing"
    echo -e "   ------------------------------------"
    read -p "   Please select a number 1-2 or any other key (random) : " host
    echo ""
    if [[ $host == "1" ]]; then
        echo -e "   \e[1;32mPlease enter your subdomain\e[0m"
        read -p "   Subdomain: " host1
        echo "IP=" >> /var/lib/kyt/ipvps.conf
        echo $host1 > /etc/xray/domain
        echo $host1 > /root/domain
        echo ""
    elif [[ $host != "1" ]]; then
        wget -q https://raw.githubusercontent.com/gotza02/vipx/main/limit/cf.sh && chmod +x cf.sh && ./cf.sh
        rm -f /root/cf.sh
        clear
    else
        print_install "Random Subdomain/Domain is Used"
        clear
    fi
}

# Reset default password
function password_default() {
    username=$(cat /usr/bin/user)
    usermod -p $(openssl passwd -1 $username) $username
}

# Install SSL certificate
function pasang_ssl() {
    clear
    print_install "Installing SSL Certificate on Domain"
    rm -rf /etc/xray/xray.key
    rm -rf /etc/xray/xray.crt
    domain=$(cat /root/domain)
    STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
    rm -rf /root/.acme.sh
    mkdir /root/.acme.sh
    systemctl stop $STOPWEBSERVER
    systemctl stop nginx
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    chmod 777 /etc/xray/xray.key
    print_success "SSL Certificate Installed"
}

function make_folder_xray() {
    rm -rf /etc/vmess/.vmess.db
    rm -rf /etc/vless/.vless.db
    rm -rf /etc/trojan/.trojan.db
    rm -rf /etc/shadowsocks/.shadowsocks.db
    rm -rf /etc/ssh/.ssh.db
    rm -rf /etc/bot/.bot.db
    rm -rf /etc/user-create/user.log
    mkdir -p /etc/bot
    mkdir -p /etc/xray
    mkdir -p /etc/vmess
    mkdir -p /etc/vless
    mkdir -p /etc/trojan
    mkdir -p /etc/shadowsocks
    mkdir -p /etc/ssh
    mkdir -p /usr/bin/xray/
    mkdir -p /var/log/xray/
    mkdir -p /var/www/html
    mkdir -p /etc/kyt/limit/vmess/ip
    mkdir -p /etc/kyt/limit/vless/ip
    mkdir -p /etc/kyt/limit/trojan/ip
    mkdir -p /etc/kyt/limit/ssh/ip
    mkdir -p /etc/limit/vmess
    mkdir -p /etc/limit/vless
    mkdir -p /etc/limit/trojan
    mkdir -p /etc/limit/ssh
    mkdir -p /etc/user-create
    chmod +x /var/log/xray
    touch /etc/xray/domain
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    touch /etc/vmess/.vmess.db
    touch /etc/vless/.vless.db
    touch /etc/trojan/.trojan.db
    touch /etc/shadowsocks/.shadowsocks.db
    touch /etc/ssh/.ssh.db
    touch /etc/bot/.bot.db
    echo "& plughin Account" >>/etc/vmess/.vmess.db
    echo "& plughin Account" >>/etc/vless/.vless.db
    echo "& plughin Account" >>/etc/trojan/.trojan.db
    echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
    echo "& plughin Account" >>/etc/ssh/.ssh.db
    echo "echo -e 'Vps Config User Account'" >> /etc/user-create/user.log
}

# Install Xray
function install_xray() {
    clear
    print_install "Installing Xray Core 1.8.1 Latest Version"
    domainSock_dir="/run/xray"; ! [ -d $domainSock_dir ] && mkdir $domainSock_dir
    chown www-data.www-data $domainSock_dir

    # Get latest Xray Core version
    latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version

    # Get server config
    wget -O /etc/xray/config.json "${REPO}config/config.json" >/dev/null 2>&1
    wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1
    domain=$(cat /etc/xray/domain)
    IPVS=$(cat /etc/xray/ipvps)
    print_success "Xray Core 1.8.1 Latest Version Installed"

    # Configure Nginx Server
    clear
    curl -s ipinfo.io/city >>/etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
    print_install "Installing Package Configuration"
    wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf" >/dev/null 2>&1
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl ${RE

PO}config/nginx.conf > /etc/nginx/nginx.conf

    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem

    # Set Permission
    chmod +x /etc/systemd/system/runn.service

    # Create Xray Service
    rm -rf /etc/systemd/system/xray.service.d
    cat >/etc/systemd/system/xray.service <<EOF
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF

    print_success "Package Configuration Installed"
}

function ssh_setup() {
    clear
    print_install "Configuring SSH"
    wget -O /etc/pam.d/common-password "${REPO}files/password"
    chmod +x /etc/pam.d/common-password

    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration

    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "

    # Edit file /etc/systemd/system/rc-local.service
    cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99

[Install]
WantedBy=multi-user.target
END

    # Configure /etc/rc.local
    cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

    # Change permission of rc.local
    chmod +x /etc/rc.local

    # Enable rc-local service
    systemctl enable rc-local
    systemctl start rc-local.service

    # Disable IPv6
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
    sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

    # Set timezone to Asia/Jakarta
    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

    # Update sshd configuration
    sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

    print_success "SSH Configuration Complete"
}

function udp_mini() {
    clear
    print_install "Installing Service Limit IP & Quota"
    wget -q https://raw.githubusercontent.com/gotza02/v1/main/config/fv-tunnel && chmod +x fv-tunnel && ./fv-tunnel

    # Installing UDP Mini
    mkdir -p /usr/local/kyt/
    wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini"
    chmod +x /usr/local/kyt/udp-mini
    wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}files/udp-mini-1.service"
    wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}files/udp-mini-2.service"
    wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}files/udp-mini-3.service"

    systemctl disable udp-mini-1
    systemctl stop udp-mini-1
    systemctl enable udp-mini-1
    systemctl start udp-mini-1
    systemctl disable udp-mini-2
    systemctl stop udp-mini-2
    systemctl enable udp-mini-2
    systemctl start udp-mini-2
    systemctl disable udp-mini-3
    systemctl stop udp-mini-3
    systemctl enable udp-mini-3
    systemctl start udp-mini-3

    print_success "Service Limit IP Installed"
}

function ssh_slowdns() {
    clear
    print_install "Installing SlowDNS Server Module"
    wget -q -O /tmp/nameserver "${REPO}files/nameserver" >/dev/null 2>&1
    chmod +x /tmp/nameserver
    bash /tmp/nameserver | tee /root/install.log
    print_success "SlowDNS Installed"
}

function sshd_setup() {
    clear
    print_install "Installing SSHD"
    wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1
    chmod 700 /etc/ssh/sshd_config
    systemctl restart ssh
    print_success "SSHD Installed"
}

function install_dropbear() {
    clear
    print_install "Installing Dropbear"
    apt install dropbear -y > /dev/null 2>&1
    wget -q -O /etc/default/dropbear "${REPO}config/dropbear.conf"
    chmod +x /etc/default/dropbear
    systemctl restart dropbear
    print_success "Dropbear Installed"
}

function install_udp_custom() {
    clear
    print_install "Installing UDP Custom"
    wget -q https://raw.githubusercontent.com/gotza02/vvip/main/ssh/udp-custom.sh
    chmod +x udp-custom.sh
    bash udp-custom.sh
    rm -f udp-custom.sh
    print_success "UDP Custom Installed"
}

function install_vnstat() {
    clear
    print_install "Installing Vnstat"
    apt install vnstat -y > /dev/null 2>&1
    systemctl restart vnstat
    apt install libsqlite3-dev -y > /dev/null 2>&1

    wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
    tar zxvf vnstat-2.6.tar.gz
    cd vnstat-2.6
    ./configure --prefix=/usr --sysconfdir=/etc && make && make install
    cd
    vnstat -u -i $NET
    sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf

    chown vnstat:vnstat /var/lib/vnstat -R
    systemctl enable vnstat
    systemctl restart vnstat
    rm -f /root/vnstat-2.6.tar.gz
    rm -rf /root/vnstat-2.6
    print_success "Vnstat Installed"
}

function install_openvpn() {
    clear
    print_install "Installing OpenVPN"
    wget ${REPO}files/openvpn && chmod +x openvpn && ./openvpn
    systemctl restart openvpn
    print_success "OpenVPN Installed"
}

function install_backup() {
    clear
    print_install "Installing Backup Server"
    apt install rclone -y
    printf "q\n" | rclone config
    wget -O /root/.config/rclone/rclone.conf "${REPO}config/rclone.conf"

    # Install Wondershaper
    cd /bin
    git clone https://github.com/magnific0/wondershaper.git
    cd wondershaper
    make install
    cd
    rm -rf wondershaper
    echo > /home/limit

    apt install msmtp-mta ca-certificates bsd-mailx -y
    cat<<EOF>>/etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account default


host smtp.gmail.com
port 587
auth on
user oceantestdigital@gmail.com
from oceantestdigital@gmail.com
password jokerman77
logfile ~/.msmtp.log

EOF

    chown -R www-data:www-data /etc/msmtprc
    wget -q -O /etc/ipserver "${REPO}files/ipserver" && bash /etc/ipserver
    print_success "Backup Server Installed"
}

function install_swap() {
    clear
    print_install "Installing 1GB Swap"

    # Install GoTop
    gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1

    # Create 1GB swap file
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile >/dev/null 2>&1
    swapon /swapfile >/dev/null 2>&1
    sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab

    # Synchronize system time
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    chronyc sourcestats -v
    chronyc tracking -v

    wget ${REPO}files/bbr.sh && chmod +x bbr.sh && ./bbr.sh
    print_success "1GB Swap Installed"
}

function install_fail2ban() {
    clear
    print_install "Installing Fail2ban"
    apt install fail2ban -y > /dev/null 2>&1
    systemctl enable fail2ban
    systemctl start fail2ban

    # Install DDOS Deflate
    if [ -d '/usr/local/ddos' ]; then
        echo; echo; echo "Please uninstall the previous version first"
        exit 0
    else
        mkdir /usr/local/ddos
    fi

    clear

    # Configure SSH banner
    echo "Banner /etc/banner" >>/etc/ssh/sshd_config
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner"@g' /etc/default/dropbear

    # Update banner
    wget -O /etc/banner "${REPO}files/banner"
    print_success "Fail2ban Installed"
}

function install_websocket() {
    clear
    print_install "Installing ePro WebSocket Proxy"
    wget -O /usr/bin/ws "${REPO}files/ws" >/dev/null 2>&1
    wget -O /usr/bin/tun.conf "${REPO}config/tun.conf" >/dev/null 2>&1
    wget -O /etc/systemd/system/ws.service "${REPO}files/ws.service" >/dev/null 2>&1
    chmod +x /etc/systemd/system/ws.service
    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf
    systemctl disable ws
    systemctl stop ws
    systemctl enable ws
    systemctl start ws
    systemctl restart ws

    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1

    wget -O /usr/sbin/ftvpn "${REPO}files/ftvpn" >/dev/null 2>&1
    chmod +x /usr/sbin/ftvpn

    # Configure IPtables
    iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
    iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
    iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
    iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
    iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
    iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
    iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
    iptables-save > /etc/iptables.up.rules
    iptables-restore -t < /etc/iptables.up.rules
    netfilter-persistent save
    netfilter-persistent reload

    # Remove unnecessary files
    cd
    apt autoclean -y >/dev/null 2>&1
    apt autoremove -y >/dev/null 2>&1
    print_success "ePro WebSocket Proxy Installed"
}

function restart_services() {
    clear
    print_install "Restarting All Services"
    systemctl daemon-reload
    systemctl restart nginx
    systemctl restart xray
    systemctl restart dropbear
    systemctl restart ssh
    systemctl restart openvpn
    systemctl restart cron
    systemctl restart fail2ban
    systemctl restart vnstat
    systemctl restart ws
    systemctl restart udp-mini-1
    systemctl restart udp-mini-2
    systemctl restart udp-mini-3
    systemctl restart rc-local

    # Set up daily reboot cron job
    echo "0 5 * * * root /usr/sbin/reboot" > /etc/cron.d/daily_reboot

    # Configure kernel parameters
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.d/99-sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.d/99-sysctl.conf
    sysctl -p

    print_success "All Services Restarted"
}

function install_menu() {
    clear
    print_install "Installing Menu Packet"
    wget ${REPO}menu/menu.zip
    unzip menu.zip
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    rm -rf menu
    rm -rf menu.zip
}

function configure_profile() {
    cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ "$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF

    mkdir -p /root/.info
    curl -sS "ipinfo.io/org?token=7a814b6263b02c" > /root/.info/.isp
    curl -sS "ipinfo.io/city?token=7a814b6263b02c" > /root/.info/.city
    cat >/etc/cron.d/xp_all <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		2 0 * * * root /usr/local/sbin/xp
	END
    cat >/etc/cron.d/logclean <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		*/20 * * * * root /usr/local/sbin/clearlog
		END
    chmod 644 /root/.profile

    cat >/etc/cron.d/daily_reboot <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		0 5 * * * root /sbin/reboot
	END
    cat >/etc/cron.d/limit_ip <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		*/2 * * * * root /usr/local/sbin/limit-ip
	END
    cat >/etc/cron.d/limit_ip2 <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		*/2 * * * * root /usr/bin/limit-ip
	END
    echo "*/1 * * * *

 root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
    service cron restart
    cat >/home/daily_reboot <<-END
		5
	END

    cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99

[Install]
WantedBy=multi-user.target
EOF

    echo "/bin/false" >>/etc/shells
    echo "/usr/sbin/nologin" >>/etc/shells

    cat >/etc/rc.local <<EOF
#!/bin/sh -e
# rc.local
# By default this script does nothing.
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF

    chmod +x /etc/rc.local
}

function enable_services() {
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable rc-local
    systemctl enable cron
    systemctl enable netfilter-persistent
    systemctl restart nginx
    systemctl restart xray
    systemctl restart cron
}

function install_service_monitor() {
    # Check if the script is being run with sudo
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root. Please run with sudo."
        exit 1
    fi

    # Get the path of the current script
    script_path=$(realpath "$0")
    script_dir=$(dirname "$script_path")

    # Create the systemd service file
    service_file="/etc/systemd/system/service_monitor.service"
    cat > "$service_file" <<EOL
[Unit]
Description=Service Monitor
After=network.target

[Service]
ExecStart=$script_dir/service_monitor.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOL

    # Create the service monitor script
    monitor_script="$script_dir/service_monitor.sh"
    cat > "$monitor_script" <<'EOL'
# Function to check and restart service
check_and_restart_service() {
    service_name=$1
    service_status=$(systemctl is-active "$service_name")

    if [ "$service_status" = "active" ]; then
        echo "$(date): $service_name is running"
    else
        echo "$(date): $service_name is not running, restarting..."
        systemctl restart "$service_name"
        sleep 5

        service_status=$(systemctl is-active "$service_name")
        if [ "$service_status" = "active" ]; then
            echo "$(date): $service_name has been restarted and is now running"
        else
            echo "$(date): $service_name failed to restart"
        fi
    fi
}

# Continuously check and restart services if needed
while true; do
    # Check and restart HAProxy if needed
    check_and_restart_service haproxy

    # Check and restart Nginx if needed
    check_and_restart_service nginx

    # Check and restart Xray if needed
    check_and_restart_service xray

    # Wait for 30 seconds before the next check
    sleep 30
done
EOL

    # Make the service monitor script executable
    chmod +x "$monitor_script"

    # Reload systemd daemon
    systemctl daemon-reload

    # Enable the service to start on boot
    systemctl enable service_monitor.service

    # Start the service
    systemctl start service_monitor.service

    echo "Service monitor has been installed and started."
}

function instal() {
    clear

    is_root
    first_setup
    nginx_install
    base_package
    make_folder_xray
    pasang_domain
    password_default
    pasang_ssl
    install_xray
    ssh_setup
    udp_mini
    ssh_slowdns
    sshd_setup
    install_dropbear
    install_udp_custom
    install_vnstat
    install_openvpn
    install_backup
    install_swap
    install_fail2ban
    install_websocket
    restart_services

    # Install and configure service monitor
    install_service_monitor

    install_menu
    configure_profile
    enable_services
}

if [ ! -d "/etc/xray" ]; then
    instal
else
    instal
    exit 1
fi

echo ""
secs_to_human "$(($(date +%s) - ${start}))"
echo ""
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE

wget -O /usr/local/bin/block.sh https://raw.githubusercontent.com/gotza02/v1/main/block.sh

# Set permissions to allow script execution
chmod +x /usr/local/bin/block.sh

# Create systemd service file
cat > /etc/systemd/system/block.service <<EOL
[Unit]
Description=Block IP Script
After=network.target

[Service]
ExecStart=/usr/local/bin/block.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd and enable block service
systemctl daemon-reload
systemctl enable block.service
systemctl start block.service

echo -e "${green} Script Successfully Installed"
echo -e "${YELLOW}----------------${NC}"
echo -e "${YELLOW}[${NC} ${green}AUTOSCRIPT PREMIUM ${NC}${YELLOW}]${NC}"
echo -e "${YELLOW}----------------${NC}"

read -n 1 -s -r -p "Press any key to reboot"
reboot
