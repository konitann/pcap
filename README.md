# 概要
libpcapを使用した自作tcpdump
# 実行手順
## 1.コンパイル
```
cc -DUSE_PCAP_FINDALLDEVS main.c -o my_program -lpcap
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