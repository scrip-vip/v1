#!/bin/bash
# Edition : Stable Edition V7.0
# Author  : Geo Project
# (C) Copyright 2024

set -e

# Color definitions
RED='\e[1;31m'
GREEN='\e[0;32m'
PURPLE='\e[0;35m'
ORANGE='\e[0;33m'
NC='\e[0m'

clear

echo -e "${GREEN}Installing and Optimizing VPS for Maximum Internet Speed${NC}"
echo -e "Please wait, advanced optimization will start shortly..."
sleep 2
clear

SYSCTL_CONF="/etc/sysctl.conf"
LIMITS_CONF="/etc/security/limits.conf"
MODULES_CONF="/etc/modules-load.d/modules.conf"

add_line_if_not_exists() {
    grep -qF -- "$2" "$1" || echo "$2" >> "$1"
}

install_bbr() {
    echo -e "${GREEN}Installing TCP BBR...${NC}"
    if lsmod | grep -q bbr; then
        echo -e "${GREEN}TCP BBR already installed.${NC}"
        return 0
    fi

    modprobe tcp_bbr
    add_line_if_not_exists "$MODULES_CONF" "tcp_bbr"
    add_line_if_not_exists "$SYSCTL_CONF" "net.core.default_qdisc = fq"
    add_line_if_not_exists "$SYSCTL_CONF" "net.ipv4.tcp_congestion_control = bbr"
    sysctl -p

    if sysctl net.ipv4.tcp_available_congestion_control | grep -q bbr && \
       sysctl net.ipv4.tcp_congestion_control | grep -q bbr && \
       lsmod | grep -q "tcp_bbr"; then
        echo -e "${GREEN}TCP BBR installed successfully!${NC}"
    else
        echo -e "${RED}Failed to install BBR!${NC}"
        exit 1
    fi
}

optimize_parameters() {
    echo -e "${GREEN}Optimizing system parameters for high-speed internet...${NC}"

    # Load required modules
    modprobe ip_conntrack

    # Optimize file descriptor limits
    add_line_if_not_exists "$LIMITS_CONF" "* soft nofile 1048576"
    add_line_if_not_exists "$LIMITS_CONF" "* hard nofile 1048576"
    add_line_if_not_exists "$LIMITS_CONF" "root soft nofile 1048576"
    add_line_if_not_exists "$LIMITS_CONF" "root hard nofile 1048576"

    # Optimize sysctl parameters
    declare -A sysctl_params=(
        ["net.ipv4.conf.all.route_localnet"]="1"
        ["net.ipv4.ip_forward"]="1"
        ["net.ipv4.conf.all.forwarding"]="1"
        ["net.ipv4.conf.default.forwarding"]="1"
        ["net.ipv6.conf.all.forwarding"]="1"
        ["net.ipv6.conf.default.forwarding"]="1"
        ["net.ipv6.conf.lo.forwarding"]="1"
        ["net.ipv6.conf.all.disable_ipv6"]="0"
        ["net.ipv6.conf.default.disable_ipv6"]="0"
        ["net.ipv6.conf.lo.disable_ipv6"]="0"
        ["net.ipv6.conf.all.accept_ra"]="2"
        ["net.ipv6.conf.default.accept_ra"]="2"
        ["net.core.netdev_budget"]="600"
        ["net.core.netdev_budget_usecs"]="20000"
        ["fs.file-max"]="2097152"
        ["net.core.rmem_max"]="67108864"
        ["net.core.wmem_max"]="67108864"
        ["net.core.rmem_default"]="67108864"
        ["net.core.wmem_default"]="67108864"
        ["net.core.optmem_max"]="65536"
        ["net.core.somaxconn"]="32768"
        ["net.ipv4.tcp_fastopen"]="3"
        ["net.ipv4.tcp_rmem"]="4096 87380 67108864"
        ["net.ipv4.tcp_wmem"]="4096 65536 67108864"
        ["net.ipv4.udp_rmem_min"]="8192"
        ["net.ipv4.udp_wmem_min"]="8192"
        ["net.ipv4.tcp_mtu_probing"]="1"
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv4.tcp_rfc1337"]="1"
        ["net.ipv4.tcp_timestamps"]="1"
        ["net.ipv4.tcp_tw_reuse"]="1"
        ["net.ipv4.tcp_fin_timeout"]="15"
        ["net.ipv4.ip_local_port_range"]="1024 65535"
        ["net.ipv4.tcp_max_tw_buckets"]="2000000"
        ["net.ipv4.tcp_slow_start_after_idle"]="0"
        ["net.ipv4.tcp_max_syn_backlog"]="32768"
        ["net.core.default_qdisc"]="fq"
        ["net.ipv4.tcp_congestion_control"]="bbr"
        ["net.ipv4.tcp_notsent_lowat"]="16384"
        ["net.ipv4.tcp_no_metrics_save"]="1"
        ["net.ipv4.tcp_ecn"]="2"
        ["net.ipv4.tcp_ecn_fallback"]="1"
        ["net.ipv4.tcp_frto"]="0"
        ["vm.swappiness"]="10"
        ["vm.overcommit_memory"]="1"
        ["kernel.pid_max"]="4194304"
        ["net.ipv4.neigh.default.gc_thresh3"]="8192"
        ["net.ipv4.neigh.default.gc_thresh2"]="4096"
        ["net.ipv4.neigh.default.gc_thresh1"]="2048"
        ["net.ipv6.neigh.default.gc_thresh3"]="8192"
        ["net.ipv6.neigh.default.gc_thresh2"]="4096"
        ["net.ipv6.neigh.default.gc_thresh1"]="2048"
        ["net.netfilter.nf_conntrack_max"]="2000000"
        ["net.nf_conntrack_max"]="2000000"
        ["vm.min_free_kbytes"]="65536"
        ["kernel.sched_migration_cost_ns"]="5000000"
        ["kernel.sched_autogroup_enabled"]="0"
    )

    for key in "${!sysctl_params[@]}"; do
        add_line_if_not_exists "$SYSCTL_CONF" "$key = ${sysctl_params[$key]}"
    done

    # Apply sysctl changes
    sysctl -p

    echo -e "${GREEN}Parameters optimized successfully for high-speed internet.${NC}"
}

configure_iptables() {
    echo -e "${GREEN}Configuring IPtables to accept all connections...${NC}"

    # Clear existing rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X

    # Set default policies to ACCEPT
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT

    # Allow established and related connections
    iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT

    # Save IPtables rules
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4
        echo -e "${GREEN}IPtables rules saved.${NC}"
    else
        echo -e "${ORANGE}iptables-save not found. IPtables rules not saved persistently.${NC}"
    fi

    echo -e "${GREEN}IPtables configured to accept all connections.${NC}"
}

optimize_network_interface() {
    echo -e "${GREEN}Optimizing network interface...${NC}"
    
    # Enable TCP timestamps and Generic Receive Offload
    for interface in $(ls /sys/class/net/ | grep -v lo); do
        ethtool -K $interface tx-tcp-segmentation on
        ethtool -K $interface gro on
        echo -e "${GREEN}Optimized $interface${NC}"
    done
}

configure_dns() {
    echo -e "${GREEN}Configuring faster DNS...${NC}"
    
    # Backup original resolv.conf
    cp /etc/resolv.conf /etc/resolv.conf.backup
    
    # Set faster DNS servers
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
    echo "nameserver 8.8.8.8" >> /etc/resolv.conf
    
    echo -e "${GREEN}DNS configured to use Cloudflare and Google DNS.${NC}"
}

# Main execution
install_bbr
optimize_parameters
configure_iptables
optimize_network_interface
configure_dns

echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}    VPS Optimization for Maximum Internet Speed Completed!    ${NC}"
echo -e "${GREEN}============================================================${NC}"

# Cleanup
rm -f /root/bbr.sh >/dev/null 2>&1

# Reboot recommendation
echo -e "${ORANGE}It is strongly recommended to reboot your system to apply all changes.${NC}"
echo -e "${ORANGE}Do you want to reboot now? (y/n)${NC}"
read -r answer
if [[ "$answer" =~ ^[Yy]$ ]]; then
    reboot
fi
