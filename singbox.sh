#!/bin/bash
# singbox一键安装脚本
# Author: Slotheve<https://slotheve.com>


RED="\033[31m"      # Error message
GREEN="\033[32m"    # Success message
YELLOW="\033[33m"   # Warning message
BLUE="\033[36m"     # Info message
PLAIN='\033[0m'


CONFIG_FILE="/usr/local/etc/sing-box/config.json"
OS=`hostnamectl | grep -i system | cut -d: -f2`

IP=`curl -sL -4 ip.sb`
VMESS="false"
VLESS="false"
TROJAN="false"
SS="false"
SOCKS="false"

ciphers=(
aes-256-gcm
2022-blake3-aes-256-gcm
chacha20-ietf-poly1305
2022-blake3-chacha20-poly1305
)

checkSystem() {
    result=$(id | awk '{print $1}')
    if [[ $result != "uid=0(root)" ]]; then
        result=$(id | awk '{print $1}')
	if [[ $result != "用户id=0(root)" ]]; then
        colorEcho $RED " 请以root身份执行该脚本"
        exit 1
	fi
    fi

    res=`which yum 2>/dev/null`
    if [[ "$?" != "0" ]]; then
        res=`which apt 2>/dev/null`
        if [[ "$?" != "0" ]]; then
            colorEcho $RED " 不受支持的Linux系统"
            exit 1
        fi
        PMT="apt"
        CMD_INSTALL="apt install -y "
        CMD_REMOVE="apt remove -y "
        CMD_UPGRADE="apt update; apt upgrade -y; apt autoremove -y"
    else
        PMT="yum"
        CMD_INSTALL="yum install -y "
        CMD_REMOVE="yum remove -y "
        CMD_UPGRADE="yum update -y"
    fi
    res=`which systemctl 2>/dev/null`
    if [[ "$?" != "0" ]]; then
        colorEcho $RED " 系统版本过低，请升级到最新版本"
        exit 1
    fi
}

colorEcho() {
    echo -e "${1}${@:2}${PLAIN}"
}

config() {
    local conf=`grep wsSettings $CONFIG_FILE`
    if [[ -z "$conf" ]]; then
        echo no
        return
    fi
    echo yes
}

status() {
    if [[ ! -f /usr/local/bin/sing-box ]]; then
        echo 0
        return
    fi
    if [[ ! -f $CONFIG_FILE ]]; then
        echo 1
        return
    fi
    port=`grep port $CONFIG_FILE| head -n 1| cut -d: -f2| tr -d \",' '`
    res=`ss -nutlp| grep ${port} | grep -i sing-box`
    if [[ -z "$res" ]]; then
        echo 2
        return
    fi
    
    if [[ `config` != "yes" ]]; then
        echo 3
    fi
}

statusText() {
    res=`status`
    case $res in
        2)
            echo -e ${GREEN}已安装${PLAIN} ${RED}未运行${PLAIN}
            ;;
        3)
            echo -e ${GREEN}已安装${PLAIN} ${GREEN}正在运行${PLAIN}
            ;;
        *)
            echo -e ${RED}未安装${PLAIN}
            ;;
    esac
}

normalizeVersion() {
    if [ -n "$1" ]; then
        case "$1" in
            v*)
                echo "$1"
            ;;
            http*)
                echo "v1.2.5"
            ;;
            *)
                echo "v$1"
            ;;
        esac
    else
        echo ""
    fi
}

# 1: new Xray. 0: no. 1: yes. 2: not installed. 3: check failed.
getVersion() {
    VER=v`/usr/local/bin/sing-box version|head -n1 | awk '{print $3}'`
    RETVAL=$?
    CUR_VER="$(normalizeVersion "$(echo "$VER" | head -n 1 | cut -d " " -f2)")"
    TAG_URL="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    NEW_VER_V="$(normalizeVersion "$(curl -s "${TAG_URL}" --connect-timeout 10| grep -Eo '\"tag_name\"(.*?)\",' | cut -d\" -f4)")"
	NEW_VER=`curl -s "${TAG_URL}" --connect-timeout 10| grep -Eo '\"tag_name\"(.*?)\",' | cut -d\" -f4 | awk -F 'v' '{print $2}'`

    if [[ $? -ne 0 ]] || [[ $NEW_VER_V == "" ]]; then
        colorEcho $RED " 检查Sing-Box版本信息失败，请检查网络"
        return 3
    elif [[ $RETVAL -ne 0 ]];then
        return 2
    elif [[ $NEW_VER_V != $CUR_VER ]];then
        return 1
    fi
    return 0
}

selectciphers() {
	for ((i=1;i<=${#ciphers[@]};i++ )); do
		hint="${ciphers[$i-1]}"
		echo -e "${green}${i}${plain}) ${hint}"
	done
	read -p " 你选择什么加密方式(默认: ${ciphers[0]}):" pick
	[ -z "$pick" ] && pick=1
	expr ${pick} + 1 &>/dev/null
	if [ $? -ne 0 ]; then
		echo -e "[${red}Error${plain}] Please enter a number"
		continue
	fi
	if [[ "$pick" -lt 1 || "$pick" -gt ${#ciphers[@]} ]]; then
		echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#ciphers[@]}"
		continue
	fi
	METHOD=${ciphers[$pick-1]}
}

getData() {
    read -p " 请输入SingBox监听端口[100-65535的一个数字]：" PORT
    [[ -z "${PORT}" ]] && PORT=`shuf -i200-65000 -n1`
    if [[ "${PORT:0:1}" = "0" ]]; then
	colorEcho ${RED}  " 端口不能以0开头"
	exit 1
    fi
    colorEcho ${BLUE}  " SingBox端口：$PORT"
    if [[ "$TROJAN" = "true" ]]; then
        echo ""
        read -p " 请设置trojan密码（不输则随机生成）:" PASSWORD
        [[ -z "$PASSWORD" ]] && PASSWORD=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1`
        colorEcho $BLUE " 密码：$PASSWORD"
		echo ""
		read -p " 请设置trojan域名（不输则随机生成）:" DOMAIN
		[[ -z "$DOMAIN" ]] && DOMAIN=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1`.xyz
		colorEcho $BLUE " 域名：$DOMAIN"
		echo ""
		read -p " 请设置域名证书（不输默认生成）:" KEY
		[[ -z "$KEY" ]] && mkdir -pv /usr/local/etc/sing-box && openssl genrsa \
		-out /usr/local/etc/sing-box/sing-box.key 2048 && chmod \
		+x /usr/local/etc/sing-box/sing-box.key && KEY="/usr/local/etc/sing-box/sing-box.key"
		colorEcho $BLUE " 密钥路径：$KEY"
		echo ""
		read -p " 请设置域名证书（不输默认生成）:" CERT
		[[ -z "$CERT" ]] && openssl req -new -x509 -days 3650 -key /usr/local/etc/sing-box/sing-box.key \
		-out /usr/local/etc/sing-box/sing-box.crt -subj "/C=US/ST=LA/L=LAX/O=Xray/OU=Trojan/CN=&DOMAIN" \
		&& chmod +x /usr/local/etc/sing-box/sing-box.crt && CERT="/usr/local/etc/sing-box/sing-box.crt"
		colorEcho $BLUE " 证书路径：$CERT"
	elif [[ "$SS" = "true" ]]; then
	    selectciphers
		if [[ "$METHOD" = "2022-blake3-aes-256-gcm" || "$METHOD" = "2022-blake3-chacha20-poly1305" ]]; then
			echo ""
			read -p " 请设置ss2022密钥（不会设置请默认生成）:" PASSWORD
			[[ -z "$PASSWORD" ]] && PASSWORD=`openssl rand -base64 32`
			colorEcho $BLUE " 密码：$PASSWORD"
		else
			echo ""
			read -p " 请设置ss密码（不输则随机生成）:" PASSWORD
			[[ -z "$PASSWORD" ]] && PASSWORD=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1`
			colorEcho $BLUE " 密码：$PASSWORD"
		fi
	elif [[ "$VLESS" = "true" ]]; then
		echo ""
		read -p " 请设置vless的UUID（不输则随机生成）:" UUID
		[[ -z "$UUID" ]] && UUID="$(cat '/proc/sys/kernel/random/uuid')"
		colorEcho $BLUE " UUID：$UUID"
	elif [[ "$SOCKS" = "true" ]]; then
		echo ""
		read -p " 请设置socks的用户名（不输则随机生成）:" USER
		[[ -z "$USER" ]] && USER=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 6 | head -n 1`
		colorEcho $BLUE " 用户名：$USER"
		echo ""
		read -p " 请设置socks的密码（不输则随机生成）:" PASSWORD
		[[ -z "$PASSWORD" ]] && PASSWORD=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1`
		colorEcho $BLUE " 密码：$PASSWORD"
	elif [[ "$VMESS" = "true" ]]; then
		echo ""
		read -p " 请设置vmess的UUID（不输则随机生成）:" UUID
		[[ -z "$UUID" ]] && UUID="$(cat '/proc/sys/kernel/random/uuid')"
		colorEcho $BLUE " UUID：$UUID"
	fi
}

setSelinux() {
    if [[ -s /etc/selinux/config ]] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config
        setenforce 0
    fi
}

archAffix() {
    case "$(uname -m)" in
        x86_64|amd64)
            ARCH="amd64"
        ;;
        armv8|aarch64)
            ARCH="arm64"
        ;;
        *)
            colorEcho $RED " 不支持的CPU架构！"
            exit 1
        ;;
    esac

	return 0
}

installSingBox() {
	archAffix
    rm -rf /tmp/sing-box
    mkdir -p /tmp/sing-box
    DOWNLOAD_LINK="https://github.com/SagerNet/sing-box/releases/download/${NEW_VER_V}/sing-box-${NEW_VER}-linux-${ARCH}.tar.gz"
    colorEcho $BLUE " 下载SingBox: ${DOWNLOAD_LINK}"
    wget -O /tmp/sing-box/sing-box.tar.gz ${DOWNLOAD_LINK}
    if [ $? != 0 ];then
        colorEcho $RED " 下载SingBox文件失败，请检查服务器网络设置"
        exit 1
    fi
    systemctl stop sing-box
    mkdir -p /usr/local/etc/sing-box /usr/local/share/sing-box && \
    tar -xvf /tmp/sing-box/sing-box.tar.gz -C /tmp/sing-box
    cp /tmp/sing-box/sing-box-${NEW_VER}-linux-${ARCH}/sing-box /usr/local/bin
    chmod +x /usr/local/bin/sing-box || {
	colorEcho $RED " SingBox安装失败"
	exit 1
    }

    cat >/etc/systemd/system/sing-box.service<<-EOF
[Unit]
Description=sing-box Service
Documentation=https://sing-box.sagernet.org/
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=30s
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
	chmod 644 ${CONFIG_FILE}
	systemctl daemon-reload
	systemctl enable sing-box.service
}

vmessConfig() {
	cat > $CONFIG_FILE<<-EOF
{
	"inbounds": [
		{
			"type": "vmess",
			"listen": "0.0.0.0",
			"listen_port": $PORT,
			"users": [{
				"uuid": "$UUID",
				"alterId": 0
			}],
			"tcp_fast_open": true,
			"udp_fragment": true,
			"sniff": true,
			"proxy_protocol": true
		}
	],
	"outbounds": [{
			"type": "direct"
		}
	]
}
EOF
}

vlessConfig() {
    cat > $CONFIG_FILE<<-EOF
{
	"inbounds": [
		{
			"type": "vless",
			"listen": "0.0.0.0",
			"listen_port": $PORT,
			"users": [{
				"uuid": "$UUID",
				"flow": ""
			}],
			"tcp_fast_open": true,
			"udp_fragment": true,
			"sniff": true,
			"proxy_protocol": true
		}
	],
	"outbounds": [{
			"type": "direct"
		}
	]
}
EOF
}

trojanConfig() {
	cat > $CONFIG_FILE<<-EOF
{
	"inbounds": [
		{
			"type": "trojan",
			"listen": "0.0.0.0",
			"listen_port": $PORT,
			"users": [{
				"password": "$PASSWORD"
			}],
			"tcp_fast_open": true,
			"udp_fragment": true,
			"sniff": true,
			"proxy_protocol": true,
			"tls": {
			"enabled": true,
			"server_name": "$DOMAIN",
			"certificate_path": "$CERT",
			"key_path": "$KEY"
			}
		}
	],
	"outbounds": [{
			"type": "direct"
		}
	]
}
EOF
}

ssConfig() {
	cat > $CONFIG_FILE<<-EOF
{
	"inbounds": [
		{
			"type": "shadowsocks",
			"listen": "0.0.0.0",
			"listen_port": $PORT,
			"method": "$METHOD",
			"password": "$PASSWORD",
			"tcp_fast_open": true,
			"udp_fragment": true,
			"sniff": true,
			"proxy_protocol": false
		}
	],
	"outbounds": [{
			"type": "direct"
		}
	]
}
EOF
}

socksConfig() {
	cat > $CONFIG_FILE<<-EOF
{
	"inbounds": [
		{
			"type": "socks",
			"listen": "0.0.0.0",
			"listen_port": $PORT,
			"users": [{
				"username": "$USER",
				"password": "$PASSWORD"
			}],
			"tcp_fast_open": true,
			"udp_fragment": true,
			"sniff": true,
			"proxy_protocol": true
		}
	],
	"outbounds": [{
			"type": "direct"
		}
	]
}
EOF
}

configSingBox() {
	mkdir -p /usr/local/sing-box
	if   [[ "$VMESS" = "true" ]]; then
		vmessConfig
	elif [[ "$VLESS" = "true" ]]; then
		vlessConfig
	elif [[ "$TROJAN" = "true" ]]; then
		trojanConfig
	elif [[ "$SS" = "true" ]]; then
		ssConfig
	elif [[ "$SOCKS" = "true" ]]; then
		socksConfig
	fi
}

install() {
	getData

	$PMT clean all
	[[ "$PMT" = "apt" ]] && $PMT update
	#echo $CMD_UPGRADE | bash
	$CMD_INSTALL wget vim tar openssl
	$CMD_INSTALL net-tools
	if [[ "$PMT" = "apt" ]]; then
		$CMD_INSTALL libssl-dev
	fi

	colorEcho $BLUE " 安装SingBox..."
	getVersion
	RETVAL="$?"
	if [[ $RETVAL == 0 ]]; then
		colorEcho $BLUE " SingBox最新版 ${CUR_VER} 已经安装"
	elif [[ $RETVAL == 3 ]]; then
		exit 1
	else
		colorEcho $BLUE " 安装SingBox ${NEW_VER_V} ，架构$(archAffix)"
		installSingBox
	fi
		configSingBox
		setSelinux
		start
		showInfo
}

update() {
	res=`status`
	if [[ $res -lt 2 ]]; then
		colorEcho $RED " SingBox未安装，请先安装！"
		return
	fi

	getVersion
	RETVAL="$?"
	if [[ $RETVAL == 0 ]]; then
		colorEcho $BLUE " SingBox最新版 ${CUR_VER} 已经安装"
	elif [[ $RETVAL == 3 ]]; then
		exit 1
	else
		colorEcho $BLUE " 安装SingBox ${NEW_VER} ，架构$(archAffix)"
		installXray
		stop
		start
		colorEcho $GREEN " 最新版SingBox安装成功！"
	fi
}

uninstall() {
	res=`status`
	if [[ $res -lt 2 ]]; then
		colorEcho $RED " SingBox未安装，请先安装！"
		return
	fi

	echo ""
	read -p " 确定卸载SingBox？[y/n]：" answer
	if [[ "${answer,,}" = "y" ]]; then
	stop
	systemctl disable xray
	rm -rf /etc/systemd/system/sing-box.service
	systemctl daemon-reload
	rm -rf /usr/local/bin/sing-box
	rm -rf /usr/local/etc/sing-box
	colorEcho $GREEN " Xray卸载成功"
	fi
}

start() {
	res=`status`
	if [[ $res -lt 2 ]]; then
		colorEcho $RED " SingBox未安装，请先安装！"
		return
	fi
	systemctl restart sing-box
	sleep 2

	port=`grep port $CONFIG_FILE| head -n 1| cut -d: -f2| tr -d \",' '`
	res=`ss -nutlp| grep ${port} | grep -i sing-box`
	if [[ "$res" = "" ]]; then
		colorEcho $RED " SingBox启动失败，请检查日志或查看端口是否被占用！"
	else
		colorEcho $BLUE " SingBox启动成功"
	fi
}

stop() {
	systemctl stop sing-box
	colorEcho $BLUE " SingBox停止成功"
}


restart() {
	res=`status`
	if [[ $res -lt 2 ]]; then
		colorEcho $RED " SingBox未安装，请先安装！"
		return
	fi

	stop
	start
}


getConfigFileInfo() {
	protocol="vmess"
	network="tcp"
	port=`grep port $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
	uuid=`grep id $CONFIG_FILE | head -n1| cut -d: -f2 | tr -d \",' '`
	alterid=`grep alterId $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
	method=`grep method $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
	username=`grep username $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
	cert=`grep certificate_path $CONFIG_FILE | tail -n1| cut -d: -f2 | tr -d \",' '`
	key=`grep key_path $CONFIG_FILE | tail -n1 | cut -d: -f2 | tr -d \",' '`
	domain=`grep server_name $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
	singbox=`grep type $CONFIG_FILE | head -n1 | cut -d: -f2 | tr -d \",' '`
	password=`grep password $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`

	if   [[ "$singbox" = "$protocol" ]]; then
		protocol="vmess"
	elif [[ "$VLESS" != "$protocol" ]]; then
		protocol="$singbox"
	fi
}

outputVmess() {
	raw="{
	\"v\":\"2\",
	\"ps\":\"\",
	\"add\":\"$IP\",
	\"port\":\"${port}\",
	\"id\":\"${uuid}\",
	\"aid\":\"$alterid\",
	\"net\":\"tcp\",
	\"type\":\"none\",
	\"host\":\"\",
	\"path\":\"\",
	\"tls\":\"\"
	}"

	link=`echo -n ${raw} | base64 -w 0`
	link="vmess://${link}"

	echo -e "   ${BLUE}协议: ${PLAIN} ${RED}${protocol}${PLAIN}"
	echo -e "   ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"
	echo -e "   ${BLUE}端口(port)：${PLAIN} ${RED}${port}${PLAIN}"
	echo -e "   ${BLUE}id(uuid)：${PLAIN} ${RED}${uuid}${PLAIN}"
	echo -e "   ${BLUE}额外id(alterid)：${PLAIN} ${RED}${alterid}${PLAIN}"
	echo -e "   ${BLUE}传输协议(network)：${PLAIN} ${RED}tcp${PLAIN}"
	echo ""
	echo -e "   ${BLUE}vmess链接:${PLAIN} $RED$link$PLAIN"
}

outputVless() {
	raw="${uuid}@$IP:${port}?encryption=none&type=tcp"

	link="vless://${raw}"

	echo -e "   ${BLUE}协议: ${PLAIN} ${RED}${protocol}${PLAIN}"
	echo -e "   ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"
	echo -e "   ${BLUE}端口(port)：${PLAIN} ${RED}${port}${PLAIN}"
	echo -e "   ${BLUE}id(uuid)：${PLAIN} ${RED}${uuid}${PLAIN}"
	echo -e "   ${BLUE}传输协议(network)：${PLAIN} ${RED}tcp${PLAIN}"
	echo ""
	echo -e "   ${BLUE}vless链接:${PLAIN} $RED$link$PLAIN"
}

outputTrojan() {
	raw="${password}@$IP:${port}?type=tcp&security=tls&sni=$domain&headerType=none"

	link="trojan://${raw}"

	echo -e "   ${BLUE}协议: ${PLAIN} ${RED}${protocol}${PLAIN}"
	echo -e "   ${BLUE}IP/域名(address): ${PLAIN} ${RED}${IP}${PLAIN}"
	echo -e "   ${BLUE}端口(port)：${PLAIN} ${RED}${port}${PLAIN}"
	echo -e "   ${BLUE}密码(password)：${PLAIN} ${RED}${password}${PLAIN}"
	echo -e "   ${BLUE}传输协议(network)：${PLAIN} ${RED}tcp${PLAIN}"
	echo -e "   ${BLUE}加密协议(security)：${PLAIN} ${RED}tls${PLAIN}"
	echo -e "   ${BLUE}域名(domain)：${PLAIN} ${RED}${domain}${PLAIN}"
	echo -e "   ${BLUE}证书路径(cert)：${PLAIN} ${RED}${cert}${PLAIN}"
	echo -e "   ${BLUE}密钥路径(key)：${PLAIN} ${RED}${key}${PLAIN}"
	echo ""
	echo -e "   ${BLUE}trojan链接:${PLAIN} $RED$link$PLAIN"
	echo -e "   ${BLUE}非自定义证书路径请务必开启:${PLAIN} ${YELLOW}skip-cert-verify:${PLAIN} ${RED}true${PLAIN} ${YELLOW}(允许不安全连接)${PLAIN}"
}

outputSS() {
	raw="${method}:${password}@$IP:${port}"

	link=`echo -n ${raw} | base64 -w 0`
	link="ss://${link}"

	echo -e "   ${BLUE}协议: ${PLAIN} ${RED}${protocol}${PLAIN}"
	echo -e "   ${BLUE}IP/域名(address): ${PLAIN} ${RED}${IP}${PLAIN}"
	echo -e "   ${BLUE}端口(port)：${PLAIN} ${RED}${port}${PLAIN}"
	echo -e "   ${BLUE}密码(password)：${PLAIN} ${RED}${password}${PLAIN}"
	echo -e "   ${BLUE}加密协议(method)：${PLAIN} ${RED}${method}${PLAIN}"
	echo -e "   ${BLUE}传输协议(network)：${PLAIN} ${RED}tcp${PLAIN}" 
	echo ""
	echo -e "   ${BLUE}ss链接:${PLAIN} $RED$link$PLAIN"
}

outputSocks() {
	echo -e "   ${BLUE}协议: ${PLAIN} ${RED}${protocol}${PLAIN}"
	echo -e "   ${BLUE}IP/域名(address): ${PLAIN} ${RED}${IP}${PLAIN}"
	echo -e "   ${BLUE}端口(port)：${PLAIN} ${RED}${port}${PLAIN}"
	echo -e "   ${BLUE}用户名(username)：${PLAIN} ${RED}${username}${PLAIN}"
	echo -e "   ${BLUE}密码(password)：${PLAIN} ${RED}${password}${PLAIN}"
}

showInfo() {
	res=`status`
	if [[ $res -lt 2 ]]; then
		colorEcho $RED " SingBox未安装，请先安装！"
		return
	fi

	echo ""
	echo -n -e " ${BLUE}SingBox运行状态：${PLAIN}"
	statusText
	echo -e " ${BLUE}SingBox配置文件: ${PLAIN} ${RED}${CONFIG_FILE}${PLAIN}"
	colorEcho $BLUE " SingBox配置信息："

	getConfigFileInfo
	if   [[ "$protocol" = vmess ]]; then
		outputVmess
	elif [[ "$protocol" = vless ]]; then
		outputVless
	elif [[ "$protocol" = trojan ]]; then
		outputTrojan
	elif [[ "$protocol" = shadowsocks ]]; then
		outputSS
	elif [[ "$protocol" = socks ]]; then
		outputSocks
	fi
}

showLog() {
	res=`status`
	if [[ $res -lt 2 ]]; then
		colorEcho $RED " SingBox未安装，请先安装！"
		return
	fi

	journalctl -xen -u sing-box --no-pager
}

menu() {
	clear
	echo "#################################################################"
	echo -e "#                     ${RED}SingBox一键安装脚本${PLAIN}                       #"
	echo -e "# ${GREEN}作者${PLAIN}: 怠惰(Slotheve)                                          #"
	echo -e "# ${GREEN}网址${PLAIN}: https://slotheve.com                                    #"
	echo -e "# ${GREEN}TG号${PLAIN}: https://t.me/slotheve                                   #"
	echo "#################################################################"
	echo " -----------------------------------------"
	colorEcho $YELLOW "  全协议支持UDP over TCP , 且ss/socks支持原生UDP"
	echo -e "  ${GREEN}1.${PLAIN}  安装vmess"
	echo -e "  ${GREEN}2.${PLAIN}  安装vless"
	echo -e "  ${GREEN}3.${PLAIN}  安装Trojan"
	echo -e "  ${GREEN}4.${PLAIN}  安装Shadowsocks"
	echo -e "  ${GREEN}5.${PLAIN}  安装Socks ${RED}不推荐${PLAIN}"
	echo -e "  ${GREEN}6.${PLAIN}  ${YELLOW}切换Snell脚本${PLAIN}"
	echo " --------------------"
	echo -e "  ${GREEN}7.${PLAIN}  更新SingBox"
	echo -e "  ${GREEN}8.${PLAIN}  ${RED}卸载SingBox${PLAIN}"
	echo " --------------------"
	echo -e "  ${GREEN}9.${PLAIN}  启动SingBox"
	echo -e "  ${GREEN}10.${PLAIN} 重启SingBox"
	echo -e "  ${GREEN}11.${PLAIN} 停止SingBox"
	echo " --------------------"
	echo -e "  ${GREEN}12.${PLAIN} 查看SingBox配置"
	echo -e "  ${GREEN}13.${PLAIN} 查看SingBox日志"
	echo " --------------------"
	echo -e "  ${GREEN}0.${PLAIN}  退出"
	echo ""
	echo -n " 当前状态："
	statusText
	echo 

	read -p " 请选择操作[0-8]：" answer
	case $answer in
		0)
			exit 0
			;;
		1)
			VMESS="true"
			install
			;;
		2)
			VLESS="true"
			install
			;;
		3)
			TROJAN="true"
			install
			;;
		4)
			SS="true"
			install
			;;
		5)
			SOCKS="true"
			install
			;;
		6)
			bash <(curl -fsSL https://raw.githubusercontent.com/Slotheve/Snell/main/snell.sh)
			;;
		7)
			update
			;;
		8)
			uninstall
			;;
		9)
			start
			;;
		10)
			restart
			;;
		11)
			stop
			;;
		12)
			showInfo
			;;
		13)
			showLog
			;;
		*)
			colorEcho $RED " 请选择正确的操作！"
			exit 1
			;;
	esac
}

checkSystem

action=$1
[[ -z $1 ]] && action=menu
case "$action" in
	menu|update|uninstall|start|restart|stop|showInfo|showLog)
		${action}
		;;
	*)
		echo " 参数错误"
		echo " 用法: `basename $0` [menu|update|uninstall|start|restart|stop|showInfo|showLog]"
		;;
esac
