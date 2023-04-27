# SingBox服务端搭建VMESS/VLESS/TROJAN/SHADOWSOCKS

- 自用脚本,此脚本只为隧道或IPLC/IEPL中转而生,无任何伪装
- Trojan的tls除非自定义证书路径,否则也是本地生成的无效证书
- Trojan非自定义证书路径请务必开启: skip-cert-verify: true

## 一键脚本
```yaml
bash <(curl -fsSL https://raw.githubusercontent.com/Slotheve/SingBox/main/singbox.sh)
```
