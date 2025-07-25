# 概要
libpcapを使用した自作tcpdump
# 実行手順
## 1.コンパイル
```
cc -DUSE_PCAP_FINDALLDEVS main.c -lpcap
```
## 2.実行
すべての通信をキャプチャしたい場合
```
sudo ./a.out 
```
インターフェース名を指定してキャプチャしたい場合
```
sudo ./a.out -i <インターフェース名>
```
ここで、インターフェースの確認はifconfigでできる。

## 3.tcpdumpを実行したい場合
```
sudo tcpdump -i eth0 -n <プロトコル名>
```
それぞれのプロトコルは以下のコマンドで確認できる。
IP,ICMP
```
ping 8.8.8.8
```
ARP
```
arp
```
TCP
```
curl http://example.com
```
UDP
```
nc -u example.com 10000
hello,world
```