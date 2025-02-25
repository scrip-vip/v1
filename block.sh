#!/bin/bash

# ฟังก์ชันแปลงหน่วยไบต์เป็นหน่วยที่อ่านง่าย
function con() {
    local -i bytes=$1;
    if [[ $bytes -lt 1024 ]]; then
        echo "${bytes}B"
    elif [[ $bytes -lt 1048576 ]]; then
        echo "$(( (bytes + 1023)/1024 ))KB"
    elif [[ $bytes -lt 1073741824 ]]; then
        echo "$(( (bytes + 1048575)/1048576 ))MB"
    else
        echo "$(( (bytes + 1073741823)/1073741824 ))GB"
    fi
}

while true; do
    clear
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Checking user connections"

    # อ่านข้อมูล user จาก config ทั้ง vmess และ vless
    users=( `cat /etc/xray/config.json | grep '###' | cut -d ' ' -f 2 | sort | uniq`);

    for user in "${users[@]}"; do
        if [[ -z "$user" ]]; then
            continue
        fi

        # อ่าน IP ของ user จาก log ล่าสุด 500 บรรทัด
        ips_vmess=( `cat /var/log/xray/access.log | tail -n 500 | grep -w "$user" | cut -d " " -f 3 | sed 's/tcp://g' | cut -d ":" -f 1 | sort | uniq` )
        ips_vless=( `cat /var/log/xray/access.log | tail -n 500 | grep -w "$user" | cut -d " " -f 3 | sed 's/tcp://g' | cut -d ":" -f 1 | sort | uniq` )

        # ตรวจสอบว่ามี IP อยู่ในระบบหรือไม่
        if [ ${#ips_vmess[@]} -eq 0 ] && [ ${#ips_vless[@]} -eq 0 ]; then
            continue
        fi

        # รวม IP ของ vmess และ vless เข้าด้วยกัน
        ips=( "${ips_vmess[@]}" "${ips_vless[@]}" )
        ips=( $(echo "${ips[@]}" | tr ' ' '\n' | sort -u))

        echo "User: $user"

        # นับจำนวน IP และแสดงผล
        ip_count=${#ips[@]}
        echo "Total IPs: $ip_count"

        # แสดงรายการ IP
        echo "IP addresses:"
        for ip in "${ips[@]}"; do
            echo "- $ip"
        done

        # แสดงจำนวน IP ที่อนุญาต
        ip_limit=$(cat /etc/kyt/limit/vmess/ip/${user} /etc/kyt/limit/vless/ip/${user} 2>/dev/null | head -n1)
        echo "IP Limit: $ip_limit"

        # คำนวณและแสดงปริมาณการใช้งาน
        byte=$(cat /etc/vmess/${user} /etc/vless/${user} 2>/dev/null | head -n1)
        usage=$(con ${byte})
        limit=$(cat /etc/limit/vmess/${user} /etc/limit/vless/${user} 2>/dev/null | head -n1)
        limit_usage=$(con ${limit})
        echo "Usage: $usage / $limit_usage"

        # แสดงเวลา Login ล่าสุด
        last_login=$(cat /var/log/xray/access.log | grep -w "$user" | tail -n 1 | cut -d " " -f 2)
        echo "Last login: $last_login"

        # ตรวจสอบและแสดง IP ที่จะถูก block
        if [[ $ip_count -gt $ip_limit ]]; then
            # เลือก IP ที่จะ block
            block_ips=("${ips[@]:0:$((ip_count - ip_limit))}")
            echo "IPs to be blocked:"
            for ip in "${block_ips[@]}"; do
                echo "- $ip"
                # Block IP ทันที
                iptables -I INPUT -s $ip -j DROP
                echo "Blocked IP: $ip"
            done

            # รอ 10 วินาทีและปลดบล็อค IP
            sleep 10

            for ip in "${block_ips[@]}"; do
                iptables -D INPUT -s $ip -j DROP
                echo "Unblocked IP: $ip"
            done
        fi

        echo "--------------------"
    done

    # รอ 5 วินาทีก่อนตรวจสอบรอบถัดไป
    sleep 5

    echo ""
done
