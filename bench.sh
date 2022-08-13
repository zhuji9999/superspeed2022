#!/usr/bin/env bash
#
# Description: A Bench Script by Teddysun
#
# Copyright (C) 2015 - 2022 Teddysun <i@teddysun.com>
# Thanks: LookBack <admin@dwhd.org>
# URL: https://teddysun.com/444.html
# https://github.com/teddysun/across/blob/master/bench.sh
#
trap _exit INT QUIT TERM

_red() {
    printf '\033[0;31;31m%b\033[0m' "$1"
}

_green() {
    printf '\033[0;31;32m%b\033[0m' "$1"
}

_yellow() {
    printf '\033[0;31;33m%b\033[0m' "$1"
}

_blue() {
    printf '\033[0;31;36m%b\033[0m' "$1"
}

_exists() {
    local cmd="$1"
    if eval type type > /dev/null 2>&1; then
        eval type "$cmd" > /dev/null 2>&1
    elif command > /dev/null 2>&1; then
        command -v "$cmd" > /dev/null 2>&1
    else
        which "$cmd" > /dev/null 2>&1
    fi
    local rt=$?
    return ${rt}
}

_exit() {
    _red "\nThe script has been terminated.\n"
    # clean up
    rm -fr speedtest.tgz speedtest-cli benchtest_*
    exit 1
}

get_opsy() {
    [ -f /etc/redhat-release ] && awk '{print $0}' /etc/redhat-release && return
    [ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
    [ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}

next() {
    printf "%-70s\n" "-" | sed 's/\s/-/g'
}

speed_test() {
    local nodeName="$2"
    [ -z "$1" ] && ./speedtest-cli/speedtest --progress=no --accept-license --accept-gdpr > ./speedtest-cli/speedtest.log 2>&1 || \
    ./speedtest-cli/speedtest --progress=no --server-id=$1 --accept-license --accept-gdpr > ./speedtest-cli/speedtest.log 2>&1
    if [ $? -eq 0 ]; then
        local dl_speed=$(awk '/Download/{print $3" "$4}' ./speedtest-cli/speedtest.log)
        local up_speed=$(awk '/Upload/{print $3" "$4}' ./speedtest-cli/speedtest.log)
        local latency=$(awk '/Latency/{print $2" "$3}' ./speedtest-cli/speedtest.log)
        if [[ -n "${dl_speed}" && -n "${up_speed}" && -n "${latency}" ]]; then
            printf "\033[0;33m%-18s\033[0;32m%-18s\033[0;31m%-20s\033[0;36m%-12s\033[0m\n" " ${nodeName}" "${up_speed}" "${dl_speed}" "${latency}"
        fi
    fi
}

speed() {
    speed_test '' 'Speedtest.net'
    speed_test '21541' 'Los Angeles, US'
    speed_test '43860' 'Dallas, US'
    speed_test '40879' 'Montreal, CA'
    speed_test '24215' 'Paris, FR'
    speed_test '28922' 'Amsterdam, NL'
    speed_test '24447' 'Shanghai, CN'
    speed_test '26352' 'Nanjing, CN'
    speed_test '27594' 'Guangzhou, CN'
    speed_test '32155' 'Hongkong, CN'
    speed_test '6527'  'Seoul, KR'
    speed_test '7311'  'Singapore, SG'
    speed_test '21569' 'Tokyo, JP'
}

io_test() {
    (LANG=C dd if=/dev/zero of=benchtest_$$ bs=512k count=$1 conv=fdatasync && rm -f benchtest_$$ ) 2>&1 | awk -F, '{io=$NF} END { print io}' | sed 's/^[ \t]*//;s/[ \t]*$//'
}

calc_size() {
    local raw=$1
    local total_size=0
    local num=1
    local unit="KB"
    if ! [[ ${raw} =~ ^[0-9]+$ ]] ; then
        echo ""
        return
    fi
    if [ "${raw}" -ge 1073741824 ]; then
        num=1073741824
        unit="TB"
    elif [ "${raw}" -ge 1048576 ]; then
        num=1048576
        unit="GB"
    elif [ "${raw}" -ge 1024 ]; then
        num=1024
        unit="MB"
    elif [ "${raw}" -eq 0 ]; then
        echo "${total_size}"
        return
    fi
    total_size=$( awk 'BEGIN{printf "%.1f", '$raw' / '$num'}' )
    echo "${total_size} ${unit}"
}

check_virt(){
    _exists "dmesg" && virtualx="$(dmesg 2>/dev/null)"
    if _exists "dmidecode"; then
        sys_manu="$(dmidecode -s system-manufacturer 2>/dev/null)"
        sys_product="$(dmidecode -s system-product-name 2>/dev/null)"
        sys_ver="$(dmidecode -s system-version 2>/dev/null)"
    else
        sys_manu=""
        sys_product=""
        sys_ver=""
    fi
    if   grep -qa docker /proc/1/cgroup; then
        virt="Docker"
    elif grep -qa lxc /proc/1/cgroup; then
        virt="LXC"
    elif grep -qa container=lxc /proc/1/environ; then
        virt="LXC"
    elif [[ -f /proc/user_beancounters ]]; then
        virt="OpenVZ"
    elif [[ "${virtualx}" == *kvm-clock* ]]; then
        virt="KVM"
    elif [[ "${sys_product}" == *KVM* ]]; then
        virt="KVM"
    elif [[ "${cname}" == *KVM* ]]; then
        virt="KVM"
    elif [[ "${cname}" == *QEMU* ]]; then
        virt="KVM"
    elif [[ "${virtualx}" == *"VMware Virtual Platform"* ]]; then
        virt="VMware"
    elif [[ "${sys_product}" == *"VMware Virtual Platform"* ]]; then
        virt="VMware"
    elif [[ "${virtualx}" == *"Parallels Software International"* ]]; then
        virt="Parallels"
    elif [[ "${virtualx}" == *VirtualBox* ]]; then
        virt="VirtualBox"
    elif [[ -e /proc/xen ]]; then
        if grep -q "control_d" "/proc/xen/capabilities" 2>/dev/null; then
            virt="Xen-Dom0"
        else
            virt="Xen-DomU"
        fi
    elif [ -f "/sys/hypervisor/type" ] && grep -q "xen" "/sys/hypervisor/type"; then
        virt="Xen"
    elif [[ "${sys_manu}" == *"Microsoft Corporation"* ]]; then
        if [[ "${sys_product}" == *"Virtual Machine"* ]]; then
            if [[ "${sys_ver}" == *"7.0"* || "${sys_ver}" == *"Hyper-V" ]]; then
                virt="Hyper-V"
            else
                virt="Microsoft Virtual Machine"
            fi
        fi
    else
        virt="Dedicated"
    fi
}

ipv4_info() {
    local org="$(wget -q -T10 -O- ipinfo.io/org)"
    local city="$(wget -q -T10 -O- ipinfo.io/city)"
    local country="$(wget -q -T10 -O- ipinfo.io/country)"
    local region="$(wget -q -T10 -O- ipinfo.io/region)"
    if [[ -n "$org" ]]; then
        echo " Organization       : $(_blue "$org")"
    fi
    if [[ -n "$city" && -n "country" ]]; then
        echo " Location           : $(_blue "$city / $country")"
    fi
    if [[ -n "$region" ]]; then
        echo " Region             : $(_yellow "$region")"
    fi
    if [[ -z "$org" ]]; then
        echo " Region             : $(_red "No ISP detected")"
    fi
}

install_speedtest() {
    if [ ! -e "./speedtest-cli/speedtest" ]; then
        sys_bit=""
        local sysarch="$(uname -m)"
        if [ "${sysarch}" = "unknown" ] || [ "${sysarch}" = "" ]; then
            local sysarch="$(arch)"
        fi
        if [ "${sysarch}" = "x86_64" ]; then
            sys_bit="x86_64"
        fi
        if [ "${sysarch}" = "i386" ] || [ "${sysarch}" = "i686" ]; then
            sys_bit="i386"
        fi
        if [ "${sysarch}" = "armv8" ] || [ "${sysarch}" = "armv8l" ] || [ "${sysarch}" = "aarch64" ] || [ "${sysarch}" = "arm64" ]; then
            sys_bit="aarch64"
        fi
        if [ "${sysarch}" = "armv7" ] || [ "${sysarch}" = "armv7l" ]; then
            sys_bit="armhf"
        fi
        if [ "${sysarch}" = "armv6" ]; then
            sys_bit="armel"
        fi
        [ -z "${sys_bit}" ] && _red "Error: Unsupported system architecture (${sysarch}).\n" && exit 1
        url1="https://install.speedtest.net/app/cli/ookla-speedtest-1.1.1-linux-${sys_bit}.tgz"
        url2="https://dl.lamp.sh/files/ookla-speedtest-1.1.1-linux-${sys_bit}.tgz"
        wget --no-check-certificate -q -T10 -O speedtest.tgz ${url1}
        if [ $? -ne 0 ]; then
            wget --no-check-certificate -q -T10 -O speedtest.tgz ${url2}
            [ $? -ne 0 ] && _red "Error: Failed to download speedtest-cli.\n" && exit 1
        fi
        mkdir -p speedtest-cli && tar zxf speedtest.tgz -C ./speedtest-cli && chmod +x ./speedtest-cli/speedtest
        rm -f speedtest.tgz
    fi
    printf "%-18s%-18s%-20s%-12s\n" " Node Name" "Upload Speed" "Download Speed" "Latency"
}

print_intro() {
    echo "-------------------- A Bench.sh Script By Teddysun -------------------"
    echo " Version            : $(_green v2022-06-01)"
    echo " Usage              : $(_red "wget -qO- bench.sh | bash")"
}

# Get System information
get_system_info() {
    cname=$( awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
    cores=$( awk -F: '/processor/ {core++} END {print core}' /proc/cpuinfo )
    freq=$( awk -F'[ :]' '/cpu MHz/ {print $4;exit}' /proc/cpuinfo )
    ccache=$( awk -F: '/cache size/ {cache=$2} END {print cache}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
    cpu_aes=$( grep -i 'aes' /proc/cpuinfo )
    cpu_virt=$( grep -Ei 'vmx|svm' /proc/cpuinfo )
    tram=$( LANG=C; free | awk '/Mem/ {print $2}' )
    tram=$( calc_size $tram )
    uram=$( LANG=C; free | awk '/Mem/ {print $3}' )
    uram=$( calc_size $uram )
    swap=$( LANG=C; free | awk '/Swap/ {print $2}' )
    swap=$( calc_size $swap )
    uswap=$( LANG=C; free | awk '/Swap/ {print $3}' )
    uswap=$( calc_size $uswap )
    up=$( awk '{a=$1/86400;b=($1%86400)/3600;c=($1%3600)/60} {printf("%d days, %d hour %d min\n",a,b,c)}' /proc/uptime )
    if _exists "w"; then
        load=$( LANG=C; w | head -1 | awk -F'load average:' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//' )
    elif _exists "uptime"; then
        load=$( LANG=C; uptime | head -1 | awk -F'load average:' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//' )
    fi
    opsy=$( get_opsy )
    arch=$( uname -m )
    if _exists "getconf"; then
        lbit=$( getconf LONG_BIT )
    else
        echo ${arch} | grep -q "64" && lbit="64" || lbit="32"
    fi
    kern=$( uname -r )
    disk_total_size=$( LANG=C; df -t simfs -t ext2 -t ext3 -t ext4 -t btrfs -t xfs -t vfat -t ntfs -t swap --total 2>/dev/null | grep total | awk '{ print $2 }' )
    disk_total_size=$( calc_size $disk_total_size )
    disk_used_size=$( LANG=C; df -t simfs -t ext2 -t ext3 -t ext4 -t btrfs -t xfs -t vfat -t ntfs -t swap --total 2>/dev/null | grep total | awk '{ print $3 }' )
    disk_used_size=$( calc_size $disk_used_size )
    tcpctrl=$( sysctl net.ipv4.tcp_congestion_control | awk -F ' ' '{print $3}' )
}
# Print System information
print_system_info() {
    if [ -n "$cname" ]; then
        echo " CPU Model          : $(_blue "$cname")"
    else
        echo " CPU Model          : $(_blue "CPU model not detected")"
    fi
    if [ -n "$freq" ]; then
        echo " CPU Cores          : $(_blue "$cores @ $freq MHz")"
    else
        echo " CPU Cores          : $(_blue "$cores")"
    fi
    if [ -n "$ccache" ]; then
        echo " CPU Cache          : $(_blue "$ccache")"
    fi
    if [ -n "$cpu_aes" ]; then
        echo " AES-NI             : $(_green "Enabled")"
    else
        echo " AES-NI             : $(_red "Disabled")"
    fi
    if [ -n "$cpu_virt" ]; then
        echo " VM-x/AMD-V         : $(_green "Enabled")"
    else
        echo " VM-x/AMD-V         : $(_red "Disabled")"
    fi
    echo " Total Disk         : $(_yellow "$disk_total_size") $(_blue "($disk_used_size Used)")"
    echo " Total Mem          : $(_yellow "$tram") $(_blue "($uram Used)")"
    if [ "$swap" != "0" ]; then
        echo " Total Swap         : $(_blue "$swap ($uswap Used)")"
    fi
    echo " System uptime      : $(_blue "$up")"
    echo " Load average       : $(_blue "$load")"
    echo " OS                 : $(_blue "$opsy")"
    echo " Arch               : $(_blue "$arch ($lbit Bit)")"
    echo " Kernel             : $(_blue "$kern")"
    echo " TCP CC             : $(_yellow "$tcpctrl")"
    echo " Virtualization     : $(_blue "$virt")"
}

print_io_test() {
    freespace=$( df -m . | awk 'NR==2 {print $4}' )
    if [ -z "${freespace}" ]; then
        freespace=$( df -m . | awk 'NR==3 {print $3}' )
    fi
    if [ ${freespace} -gt 1024 ]; then
        writemb=2048
        io1=$( io_test ${writemb} )
        echo " I/O Speed(1st run) : $(_yellow "$io1")"
        io2=$( io_test ${writemb} )
        echo " I/O Speed(2nd run) : $(_yellow "$io2")"
        io3=$( io_test ${writemb} )
        echo " I/O Speed(3rd run) : $(_yellow "$io3")"
        ioraw1=$( echo $io1 | awk 'NR==1 {print $1}' )
        [ "`echo $io1 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw1=$( awk 'BEGIN{print '$ioraw1' * 1024}' )
        ioraw2=$( echo $io2 | awk 'NR==1 {print $1}' )
        [ "`echo $io2 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw2=$( awk 'BEGIN{print '$ioraw2' * 1024}' )
        ioraw3=$( echo $io3 | awk 'NR==1 {print $1}' )
        [ "`echo $io3 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw3=$( awk 'BEGIN{print '$ioraw3' * 1024}' )
        ioall=$( awk 'BEGIN{print '$ioraw1' + '$ioraw2' + '$ioraw3'}' )
        ioavg=$( awk 'BEGIN{printf "%.1f", '$ioall' / 3}' )
        echo " I/O Speed(average) : $(_yellow "$ioavg MB/s")"
    else
        echo " $(_red "Not enough space for I/O Speed test!")"
    fi
}

print_end_time() {
    end_time=$(date +%s)
    time=$(( ${end_time} - ${start_time} ))
    if [ ${time} -gt 60 ]; then
        min=$(expr $time / 60)
        sec=$(expr $time % 60)
        echo " Finished in        : ${min} min ${sec} sec"
    else
        echo " Finished in        : ${time} sec"
    fi
    date_time=$(date '+%Y-%m-%d %H:%M:%S %Z')
    echo " Timestamp          : $date_time"
}

! _exists "wget" && _red "Error: wget command not found.\n" && exit 1
! _exists "free" && _red "Error: free command not found.\n" && exit 1
start_time=$(date +%s)
get_system_info
check_virt
clear
print_intro
next
print_system_info
ipv4_info
next
print_io_test
next
install_speedtest && speed && rm -fr speedtest-cli
next
print_end_time
next
	echo "  Wrong parameters. Use $(tput setaf 3)bash $BASH_SOURCE -help$(tput sgr0) to see parameters"
	echo "  ex: $(tput setaf 3)bash $BASH_SOURCE -info$(tput sgr0) (without quotes) for system information"
	echo ""
}

benchinit() {
	if ! hash curl 2>$NULL; then
		echo "missing dependency curl"
		echo "please install curl first"
		exit
	fi
}

CMD="$1"
PRM1="$2"
PRM2="$3"
log="$HOME/bench.log"
ARG="$BASH_SOURCE $@"
benchram="/mnt/tmpbenchram"
NULL="/dev/null"
true > $log

cancel () {
	echo ""
	rm -f test
	echo " Abort"
	if [[ -d $benchram ]]; then
		rm $benchram/zero
		umount $benchram
		rm -rf $benchram
	fi
	exit
}

trap cancel SIGINT

systeminfo () {
	# Systeminfo
	echo "" | tee -a $log
	echo " $(tput setaf 6)## System Information$(tput sgr0)"
	echo " ## System Information" >> $log
	echo "" | tee -a $log

	# OS Information (Name)
	cpubits=$( uname -m )
	if echo $cpubits | grep -q 64; then
		bits=" (64 bit)"
	elif echo $cpubits | grep -q 86; then
		bits=" (32 bit)"
	elif echo $cpubits | grep -q armv5; then
		bits=" (armv5)"
	elif echo $cpubits | grep -q armv6l; then
		bits=" (armv6l)"
	elif echo $cpubits | grep -q armv7l; then
		bits=" (armv7l)"
	else
		bits="unknown"
	fi

	if hash lsb_release 2>$NULL; then
		soalt=$(lsb_release -d)
		echo -e " OS Name     : "${soalt:13} $bits | tee -a $log
	else
		so=$(awk 'NF' /etc/issue)
		pos=$(expr index "$so" 123456789)
		so=${so/\/}
		extra=""
		if [[ "$so" == Debian*9* ]]; then
			extra="(stretch)"
		elif [[ "$so" == Debian*8* ]]; then
			extra="(jessie)"
		elif [[ "$so" == Debian*7* ]]; then
			extra="(wheezy)"
		elif [[ "$so" == Debian*6* ]]; then
			extra="(squeeze)"
		fi
		if [[ "$so" == *Proxmox* ]]; then
			so="Debian 7.6 (wheezy)";
		fi
		otro=$(expr index "$so" \S)
		if [[ "$otro" == 2 ]]; then
			so=$(cat /etc/*-release)
			pos=$(expr index "$so" NAME)
			pos=$((pos-2))
			so=${so/\/}
		fi
		echo -e " OS Name     : "${so:0:($pos+2)}$extra$bits | tr -d '\n' | tee -a $log
		echo "" | tee -a $log
	fi
	sleep 0.1

	#Detect virtualization
	if hash ifconfig 2>$NULL; then
		eth=$(ifconfig)
	fi
	virtualx=$(dmesg)
	if [[ -f /proc/user_beancounters ]]; then
		virtual="OpenVZ"
	elif [[ "$virtualx" == *kvm-clock* ]]; then
		virtual="KVM"
	elif [[ "$virtualx" == *"VMware Virtual Platform"* ]]; then
		virtual="VMware"
	elif [[ "$virtualx" == *"Parallels Software International"* ]]; then
		virtual="Parallels"
	elif [[ "$virtualx" == *VirtualBox* ]]; then
		virtual="VirtualBox"
	elif [[ "$eth" == *eth0* ]];then
		virtual="Dedicated"
	elif [[ -e /proc/xen ]]; then
		virtual="Xen"
	fi

	#Kernel
	echo " Kernel      : $virtual / $(uname -r)" | tee -a $log
	sleep 0.1

	# Hostname
	echo " Hostname    : $(hostname)" | tee -a $log
	sleep 0.1

	# CPU Model Name
	cpumodel=$( awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo )
	echo " CPU Model   :$cpumodel" | tee -a $log
	sleep 0.1

	# CPU Cores
	cores=$( awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo )
	corescache=$( awk -F: '/cache size/ {cache=$2} END {print cache}' /proc/cpuinfo )
	freq=$( awk -F: ' /cpu MHz/ {freq=$2} END {print freq}' /proc/cpuinfo )
	if [[ $cores == "1" ]]; then
		echo " CPU Cores   : $cores core @ $freq MHz" | tee -a $log
	else
		echo " CPU Cores   : $cores cores @ $freq MHz" | tee -a $log
	fi
	sleep 0.1
	echo " CPU Cache   :$corescache" | tee -a $log
	sleep 0.1

	# RAM Information
	tram="$( free -m | grep Mem | awk 'NR=1 {print $2}' ) MiB"
	fram="$( free -m | grep Mem | awk 'NR=1 {print $7}' ) MiB"
	fswap=$( free -m | grep Swap | awk 'NR=1 {print $4}' )MiB
	echo " Total RAM   : $tram (Free $fram)" | tee -a $log
	sleep 0.1

	# Swap Information
	tswap="$( free -m | grep Swap | awk 'NR=1 {print $2}' ) MiB"
	tswap0=$( grep SwapTotal < /proc/meminfo | awk 'NR=1 {print $2$3}' )
	if [[ "$tswap0" == "0kB" ]]; then
		echo " Total SWAP  : SWAP not enabled" | tee -a $log
	else
		echo " Total SWAP  : $tswap (Free $fswap)" | tee -a $log
	fi
	sleep 0.1

	# HDD information
	hdd=$( df -h --total --local -x tmpfs | grep 'total' | awk '{print $2}' )B
	hddfree=$( df -h --total | grep 'total' | awk '{print $5}' )
	echo " Total Space : $hdd ($hddfree used)" | tee -a $log
	sleep 0.1

	# Uptime
	secs=$( awk '{print $1}' /proc/uptime | cut -f1 -d"." )
	if [[ $secs -lt 120 ]]; then
		sysuptime="$secs seconds"
	elif [[ $secs -lt 3600 ]]; then
		sysuptime=$( printf '%d minutes %d seconds\n' $((secs%3600/60)) $((secs%60)) )
	elif [[ $secs -lt 86400 ]]; then
		sysuptime=$( printf '%dhrs %dmin %dsec\n' $((secs/3600)) $((secs%3600/60)) $((secs%60)) )
	else
		sysuptime=$( echo $((secs/86400))"days - "$(date -d "1970-01-01 + $secs seconds" "+%Hhrs %Mmin %Ssec") )
	fi
	echo " Running for : $sysuptime" | tee -a $log
	echo "" | tee -a $log
}

echostyle(){
	if hash tput 2>$NULL; then
		echo " $(tput setaf 6)$1$(tput sgr0)"
		echo " $1" >> $log
	else
		echo " $1" | tee -a $log
	fi
}

FormatBytes() {
	bytes=${1%.*}
	local Mbps=$( printf "%s" "$bytes" | awk '{ printf "%.2f", $0 / 1024 / 1024 * 8 } END { if (NR == 0) { print "error" } }' )
	if [[ $bytes -lt 1000 ]]; then
		printf "%8i B/s |      N/A     "  $bytes
	elif [[ $bytes -lt 1000000 ]]; then
		local KiBs=$( printf "%s" "$bytes" | awk '{ printf "%.2f", $0 / 1024 } END { if (NR == 0) { print "error" } }' )
		printf "%7s KiB/s | %7s Mbps" "$KiBs" "$Mbps"
	else
		# awk way for accuracy
		local MiBs=$( printf "%s" "$bytes" | awk '{ printf "%.2f", $0 / 1024 / 1024 } END { if (NR == 0) { print "error" } }' )
		printf "%7s MiB/s | %7s Mbps" "$MiBs" "$Mbps"

		# bash way
		# printf "%4s MiB/s | %4s Mbps""$(( bytes / 1024 / 1024 ))" "$(( bytes / 1024 / 1024 * 8 ))"
	fi
}

pingtest() {
	# ping one time
	local ping_link=$( echo ${1#*//} | cut -d"/" -f1 )
	local ping_ms=$( ping -w1 -c1 $ping_link | grep 'rtt' | cut -d"/" -f5 )

	# get download speed and print
	if [[ $ping_ms == "" ]]; then
		printf " | ping error!"
	else
		printf " | ping %3i.%sms" "${ping_ms%.*}" "${ping_ms#*.}"
	fi
}

# main function for speed checking
# the report speed are average per file
speed() {
	# print name
	printf "%s" " $1" | tee -a $log

	# get download speed and print
	C_DL=$( curl -m 4 -w '%{speed_download}\n' -o $NULL -s "$2" )
	printf "%s\n" "$(FormatBytes $C_DL) $(pingtest $2)" | tee -a $log
}

# 2 location (200MB)
cdnspeedtest () {
	echo "" | tee -a $log
	echostyle "## CDN Speedtest"
	echo "" | tee -a $log
	speed "CacheFly :" "http://cachefly.cachefly.net/100mb.test"

	# google drive speed test
	TMP_COOKIES="/tmp/cookies.txt"
	TMP_FILE="/tmp/gdrive"
	DRIVE="drive.google.com"
	FILE_ID="0B1MVW1mFO2zmdGhyaUJESWROQkE"

	printf " Gdrive   :"  | tee -a $log
	curl -c $TMP_COOKIES -o $TMP_FILE -s "https://$DRIVE/uc?id=$FILE_ID&export=download"
	D_ID=$( grep "confirm=" < $TMP_FILE | awk -F "confirm=" '{ print $NF }' | awk -F "&amp" '{ print $1 }' )
	C_DL=$( curl -m 4 -Lb $TMP_COOKIES -w '%{speed_download}\n' -o $NULL \
		-s "https://$DRIVE/uc?export=download&confirm=$D_ID&id=$FILE_ID" )
	printf "%s\n" "$(FormatBytes $C_DL) $(pingtest $DRIVE)" | tee -a $log
	echo "" | tee -a $log
}

# 10 location (1GB)
northamerciaspeedtest () {
	echo "" | tee -a $log
	echostyle "## North America Speedtest"
	echo "" | tee -a $log
	speed "Softlayer, Washington, USA :" "http://speedtest.wdc04.softlayer.com/downloads/test100.zip"
	speed "SoftLayer, San Jose, USA   :" "http://speedtest.sjc01.softlayer.com/downloads/test100.zip"
	speed "SoftLayer, Dallas, USA     :" "http://speedtest.dal01.softlayer.com/downloads/test100.zip"
	speed "Vultr, New Jersey, USA     :" "https://nj-us-ping.vultr.com/vultr.com.100MB.bin"
	speed "Vultr, Chicago, USA        :" "https://il-us-ping.vultr.com/vultr.com.100MB.bin"
	speed "Vultr, Atlanta, USA        :" "https://ga-us-ping.vultr.com/vultr.com.100MB.bin"
	speed "Vultr, Miami, USA          :" "https://fl-us-ping.vultr.com/vultr.com.100MB.bin"
	speed "Vultr, Dallas, USA         :" "https://tx-us-ping.vultr.com/vultr.com.100MB.bin"
	speed "Vultr, Seattle, USA        :" "https://wa-us-ping.vultr.com/vultr.com.100MB.bin"
	speed "Vultr, Los Angeles, USA    :" "https://lax-ca-us-ping.vultr.com/vultr.com.100MB.bin"
	speed "Vultr, Silicon Valley, USA :" "https://sjo-ca-us-ping.vultr.com/vultr.com.100MB.bin"
	speed "Vultr, New York, USA       :" "https://nj-us-ping.vultr.com/vultr.com.100MB.bin"
	speed "Linode, fremont, USA       :" "http://speedtest.fremont.linode.com/100MB-fremont.bin"
	speed "Linode, atlanta, USA       :" "http://speedtest.atlanta.linode.com/100MB-atlanta.bin"
	speed "Linode, dallas, USA        :" "http://speedtest.dallas.linode.com/100MB-dallas.bin"
	speed "Linode, newark, USA        :" "http://speedtest.newark.linode.com/100MB-newark.bin"
	speed "Linode, toronto, Canada    :" "http://speedtest.toronto1.linode.com/100MB-toronto1.bin"
	speed "Ramnode, New York, USA     :" "http://lg.nyc.ramnode.com/static/100MB.test"
	speed "Ramnode, Atlanta, USA      :" "http://lg.atl.ramnode.com/static/100MB.test"
	speed "OVH, Beauharnois, Canada   :" "http://bhs.proof.ovh.net/files/100Mio.dat"
	speed "Vultr, Toronto, Canada     :" "https://tor-ca-ping.vultr.com/vultr.com.100MB.bin"
	echo ""
}

# 9 location (900MB)
europespeedtest () {
	echo "" | tee -a $log
	echostyle "## Europe Speedtest"
	echo "" | tee -a $log
	speed "Vultr, London, UK            :" "https://lon-gb-ping.vultr.com/vultr.com.100MB.bin"
	speed "Vultr, Frankfurt, DE         :" "https://fra-de-ping.vultr.com/vultr.com.100MB.bin"
	speed "Vultr, Paris, France         :" "https://par-fr-ping.vultr.com/vultr.com.100MB.bin"
	speed "Vultr, Amsterdam, NL         :" "https://ams-nl-ping.vultr.com/vultr.com.100MB.bin"
	speed "Vultr, London, UK            :" "https://lon-gb-ping.vultr.com/vultr.com.100MB.bin"
	speed "Linode, london, UK           :" "http://speedtest.london.linode.com/100MB-london.bin"
	speed "Linode, frankfurt, DE        :" "http://speedtest.frankfurt.linode.com/100MB-frankfurt.bin"
	speed "Linode, frankfurt, DE        :" "http://speedtest.frankfurt.linode.com/100MB-frankfurt.bin"
	speed "LeaseWeb, Frankfurt, Germany :" "http://mirror.de.leaseweb.net/speedtest/100mb.bin"
	speed "Hetzner, Germany             :" "https://speed.hetzner.de/100MB.bin"
	speed "Ramnode, Alblasserdam, NL    :" "http://lg.nl.ramnode.com/static/100MB.test"
	speed "EDIS, Stockholm, Sweden      :" "http://se.edis.at/100MB.test"
	speed "OVH, Roubaix, France         :" "http://rbx.proof.ovh.net/files/100Mio.dat"
	speed "Online, France               :" "http://ping.online.net/100Mo.dat"
	speed "Prometeus, Milan, Italy      :" "http://mirrors.prometeus.net/test/test100.bin"
	echo "" | tee -a $log
}

# 4 location (200MB)
exoticpeedtest () {
	echo "" | tee -a $log
	echostyle "## Exotic Speedtest"
	echo "" | tee -a $log
	speed "Vultr, Sydney, Australia    :" "https://syd-au-ping.vultr.com/vultr.com.100MB.bin"
	speed "Linode, Sydney, Australia   :" "http://speedtest.syd1.linode.com/100MB-syd1.bin"
	speed "Sydney, Australia           :" "https://syd-au-ping.vultr.com/vultr.com.100MB.bin"
	speed "Lagoon, New Caledonia       :" "http://mirror.lagoon.nc/speedtestfiles/test50M.bin"
	speed "Hosteasy, Moldova           :" "http://mirror.as43289.net/speedtest/100mb.bin"
	speed "Prima, Argentina            :" "http://sftp.fibertel.com.ar/services/file-50MB.img"
	echo "" | tee -a $log
}

# 4 location (400MB)
asiaspeedtest () {
	echo "" | tee -a $log
	echostyle "## Asia Speedtest"
	echo "" | tee -a $log
	speed "SoftLayer, Singapore       :" "http://speedtest.sng01.softlayer.com/downloads/test100.zip"
	speed "Linode, Tokyo, Japan       :" "http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin"
	speed "Linode, Singapore          :" "http://speedtest.singapore.linode.com/100MB-singapore.bin"
	speed "Linode, mumbai1, India     :" "http://speedtest.mumbai1.linode.com/100MB-mumbai1.bin"
	speed "Vultr, Tokyo, Japan        :" "https://hnd-jp-ping.vultr.com/vultr.com.100MB.bin"
	speed "Vultr, Seoul               :" "https://sel-kor-ping.vultr.com/vultr.com.100MB.bin"
	speed "Vultr, Singapore           :" "https://sgp-ping.vultr.com/vultr.com.100MB.bin"
	echo "" | tee -a $log
}

freedisk() {
	# check free space
	freespace=$( df -m . | awk 'NR==2 {print $4}' )
	if [[ $freespace -ge 1024 ]]; then
		printf "%s" $((1024*2))
	elif [[ $freespace -ge 512 ]]; then
		printf "%s" $((512*2))
	elif [[ $freespace -ge 256 ]]; then
		printf "%s" $((256*2))
	elif [[ $freespace -ge 128 ]]; then
		printf "%s" $((128*2))
	else
		printf 1
	fi
}

averageio() {
	ioraw1=$( echo $1 | awk 'NR==1 {print $1}' )
		[ "$(echo $1 | awk 'NR==1 {print $2}')" == "GB/s" ] && ioraw1=$( awk 'BEGIN{print '$ioraw1' * 1024}' )
	ioraw2=$( echo $2 | awk 'NR==1 {print $1}' )
		[ "$(echo $2 | awk 'NR==1 {print $2}')" == "GB/s" ] && ioraw2=$( awk 'BEGIN{print '$ioraw2' * 1024}' )
	ioraw3=$( echo $3 | awk 'NR==1 {print $1}' )
		[ "$(echo $3 | awk 'NR==1 {print $2}')" == "GB/s" ] && ioraw3=$( awk 'BEGIN{print '$ioraw3' * 1024}' )
	ioall=$( awk 'BEGIN{print '$ioraw1' + '$ioraw2' + '$ioraw3'}' )
	ioavg=$( awk 'BEGIN{printf "%.1f", '$ioall' / 3}' )
	printf "%s" "$ioavg"
}

cpubench() {
	if hash $1 2>$NULL; then
		io=$( ( dd if=/dev/zero bs=512K count=$2 | $1 ) 2>&1 | grep 'copied' | awk -F, '{io=$NF} END { print io}' )
		if [[ $io != *"."* ]]; then
			printf "  %4i %s" "${io% *}" "${io##* }"
		else
			printf "%4i.%s" "${io%.*}" "${io#*.}"
		fi
	else
		printf " %s not found on system." "$1"
	fi
}

iotest () {
	echo "" | tee -a $log
	echostyle "## IO Test"
	echo "" | tee -a $log

	# start testing
	writemb=$(freedisk)
	if [[ $writemb -gt 512 ]]; then
		writemb_size="$(( writemb / 2 / 2 ))MB"
		writemb_cpu="$(( writemb / 2 ))"
	else
		writemb_size="$writemb"MB
		writemb_cpu=$writemb
	fi

	# CPU Speed test
	printf " CPU Speed:\n" | tee -a $log
	printf "    bzip2 %s -" "$writemb_size" | tee -a $log
	printf "%s\n" "$( cpubench bzip2 $writemb_cpu )" | tee -a $log 
	printf "   sha256 %s -" "$writemb_size" | tee -a $log
	printf "%s\n" "$( cpubench sha256sum $writemb_cpu )" | tee -a $log
	printf "   md5sum %s -" "$writemb_size" | tee -a $log
	printf "%s\n\n" "$( cpubench md5sum $writemb_cpu )" | tee -a $log

	# Disk test
	echo " Disk Speed ($writemb_size):" | tee -a $log
	if [[ $writemb != "1" ]]; then
		io=$( ( dd bs=512K count=$writemb if=/dev/zero of=test; rm -f test ) 2>&1 | awk -F, '{io=$NF} END { print io}' )
		echo "   I/O Speed  -$io" | tee -a $log

		io=$( ( dd bs=512K count=$writemb if=/dev/zero of=test oflag=dsync; rm -f test ) 2>&1 | awk -F, '{io=$NF} END { print io}' )
		echo "   I/O Direct -$io" | tee -a $log
	else
		echo "   Not enough space to test." | tee -a $log
	fi
	echo "" | tee -a $log

	# RAM Speed test
	# set ram allocation for mount
	tram_mb="$( free -m | grep Mem | awk 'NR=1 {print $2}' )"
	if [[ tram_mb -gt 1900 ]]; then
		sbram=1024M
		sbcount=2048
	else
		sbram=$(( tram_mb / 2 ))M
		sbcount=$tram_mb
	fi
	[[ -d $benchram ]] || mkdir $benchram
	mount -t tmpfs -o size=$sbram tmpfs $benchram/
	printf " RAM Speed (%sB):\n" "$sbram" | tee -a $log
	iow1=$( ( dd if=/dev/zero of=$benchram/zero bs=512K count=$sbcount ) 2>&1 | awk -F, '{io=$NF} END { print io}' )
	ior1=$( ( dd if=$benchram/zero of=$NULL bs=512K count=$sbcount; rm -f test ) 2>&1 | awk -F, '{io=$NF} END { print io}' )
	iow2=$( ( dd if=/dev/zero of=$benchram/zero bs=512K count=$sbcount ) 2>&1 | awk -F, '{io=$NF} END { print io}' )
	ior2=$( ( dd if=$benchram/zero of=$NULL bs=512K count=$sbcount; rm -f test ) 2>&1 | awk -F, '{io=$NF} END { print io}' )
	iow3=$( ( dd if=/dev/zero of=$benchram/zero bs=512K count=$sbcount ) 2>&1 | awk -F, '{io=$NF} END { print io}' )
	ior3=$( ( dd if=$benchram/zero of=$NULL bs=512K count=$sbcount; rm -f test ) 2>&1 | awk -F, '{io=$NF} END { print io}' )
	echo "   Avg. write - $(averageio "$iow1" "$iow2" "$iow3") MB/s" | tee -a $log
	echo "   Avg. read  - $(averageio "$ior1" "$ior2" "$ior3") MB/s" | tee -a $log
	rm $benchram/zero
	umount $benchram
	rm -rf $benchram
	echo "" | tee -a $log
}

speedtestresults () {
	#Testing Speedtest
	if hash python 2>$NULL; then
		curl -Lso speedtest-cli https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py
		python speedtest-cli --share | tee -a $log
		rm -f speedtest-cli
		echo ""
	else
		echo " Python is not installed."
		echo " First install python, then re-run the script."
		echo ""
	fi
}

startedon() {
	echo "\$ $ARG" >> $log
	echo "" | tee -a $log
	benchstart=$(date +"%d-%b-%Y %H:%M:%S")
	start_seconds=$(date +%s)
	echo " Benchmark started on $benchstart" | tee -a $log
}

finishedon() {
	end_seconds=$(date +%s)
	echo " Benchmark finished in $((end_seconds-start_seconds)) seconds" | tee -a $log
	echo "   results saved on $log"
	echo "" | tee -a $log
}

sharetest() {
	case $1 in
	'ubuntu')
		share_link=$( curl -v --data-urlencode "content@$log" -d "poster=bench.log" -d "syntax=text" "https://paste.ubuntu.com" 2>&1 | \
			grep "Location" | awk '{print $3}' );;
	'haste' )
		share_link=$( curl -X POST -s -d "$(cat $log)" https://hastebin.com/documents | awk -F '"' '{print "https://hastebin.com/"$4}' );;
	'clbin' )
		share_link=$( curl -sF 'clbin=<-' https://clbin.com < $log );;
	'ptpb' )
		share_link=$( curl -sF c=@- https://ptpb.pw/?u=1 < $log );;
	esac

	# print result info
	echo " Share result:"
	echo " $share_link"
	echo ""

}

case $CMD in
	'-info'|'-information'|'--info'|'--information' )
		systeminfo;;
	'-io'|'-drivespeed'|'--io'|'--drivespeed' )
		iotest;;
	'-northamercia'|'-na'|'--northamercia'|'--na' )
		benchinit; northamerciaspeedtest;;
	'-europe'|'-eu'|'--europe'|'--eu' )
		benchinit; europespeedtest;;
	'-exotic'|'--exotic' )
		benchinit; exoticpeedtest;;
	'-asia'|'--asia' )
		benchinit; asiaspeedtest;;
	'-cdn'|'--cdn' )
		benchinit; cdnspeedtest;;
	'-b'|'--b' )
		benchinit; startedon; systeminfo; cdnspeedtest; iotest; finishedon;;
	'-a'|'-all'|'-bench'|'--a'|'--all'|'--bench' )
		benchinit; startedon; systeminfo; cdnspeedtest; northamerciaspeedtest;
		europespeedtest; exoticpeedtest; asiaspeedtest; iotest; finishedon;;
	'-speed'|'-speedtest'|'-speedcheck'|'--speed'|'--speedtest'|'--speedcheck' )
		benchinit; speedtestresults;;
	'-help'|'--help'|'help' )
		prms;;
	'-about'|'--about'|'about' )
		about;;
	*)
		howto;;
esac

case $PRM1 in
	'-share'|'--share'|'share' )
		if [[ $PRM2 == "" ]]; then
			sharetest ubuntu
		else
			sharetest $PRM2
		fi
		;;
esac

# ring a bell
printf '\007'
