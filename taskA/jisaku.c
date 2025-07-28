/*
 * if use recently libpcap, set USE_PCAP_FINDALLDEVS like following:
 *      $ cc -DUSE_PCAP_FINDALLDEVS foo.c -lpcap
 */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>

#ifdef USE_PCAP_FINDALLDEVS
/*インターフェースの検索と選択*/
int
finddev(char **xdev, pcap_if_t  **xifp)     //デバイス名(eth0),デバイスの詳細情報
{
    char       errbuf[PCAP_ERRBUF_SIZE];    //エラーメッセージ
    pcap_if_t *list;                        //pcap_findalldevsが返すデバイスリストの先頭
    pcap_if_t *u;                           //デバイスリストのポインタ
    int        ik;                          //関数の戻り値をチェックする
    char      *dev;                         //デバイス名とデバイスの詳細情報のローカル変数
    pcap_if_t *ifp;

    dev = *xdev;
    ifp = *xifp;

    ik = pcap_findalldevs(&list, errbuf);   //PCに接続されてるデバイスリストの取得
    if(ik) {
        perror("pcap_findalldevs");
        exit(91);
    }
    u = list;
    while(u) {                              //リストの先頭からデバイスを1つずつチェック
        if(u->flags & PCAP_IF_UP) {
            /* find given name */
            if(dev && strcmp(dev, u->name)) {
                ifp = u;
                break;
            }
            /* no given name; set first up interface */
            if(!dev) {
                dev = strdup(u->name);
                ifp = u;
                break;
            }
        }
        u = u->next;
    }
    if(dev) {
        *xdev = dev;
    }
    if(ifp) {
        *xifp = ifp;
    }

    return 0;
}
#endif

struct box {
    pcap_t *hand;
};


void arp(const u_char *pktdata, int pktlen){
    printf("ARP, ");

    struct ether_header *eth = (struct ether_header *)pktdata;
    struct arphdr *arp = (struct arphdr *)(pktdata + sizeof(struct ether_header));
    u_char *arp_data = (u_char *)(arp + 1);
    int arp_len;

    arp_len = sizeof(struct arphdr) + (2 * arp->ar_hln) + (2 * arp->ar_pln);

    if (ntohs(arp->ar_op) == ARPOP_REQUEST) {
        /* ARPリクエストの詳細表示 */
        struct in_addr spa_addr, tpa_addr;
        u_char *sha, *tha;

        char spa_str[INET_ADDRSTRLEN];
        char tpa_str[INET_ADDRSTRLEN];
        
        sha = arp_data;
        // 各アドレスデータをコピー
        memcpy(&spa_addr, arp_data + arp->ar_hln, arp->ar_pln);
        tha = arp_data + arp->ar_hln + arp->ar_pln;
        memcpy(&tpa_addr, arp_data + arp->ar_hln + arp->ar_pln + arp->ar_hln, arp->ar_pln);
        
        strcpy(spa_str, inet_ntoa(spa_addr));
        strcpy(tpa_str, inet_ntoa(tpa_addr));
        
        printf("Request who-has %s", tpa_str);
        if (tha[0] || tha[1] || tha[2] || tha[3] || tha[4] || tha[5]) {
            printf(" (%02x:%02x:%02x:%02x:%02x:%02x)",
                   tha[0], tha[1], tha[2], tha[3], tha[4], tha[5]);
        }
        printf(" tell %s", spa_str);

    } else if (ntohs(arp->ar_op) == ARPOP_REPLY) {
        struct in_addr spa_addr;
        u_char *sha;
        
        sha = arp_data;
        memcpy(&spa_addr, arp_data + arp->ar_hln, arp->ar_pln);
        
        printf("Reply %s is-at %02x:%02x:%02x:%02x:%02x:%02x",
               inet_ntoa(spa_addr), sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]);
    }
    printf(", length %d\n", arp_len);
}

void icmp(const u_char *data, int icmp_len, struct in_addr src_ip, struct in_addr dst_ip)
{
    struct icmp *icmp_hdr = (struct icmp *)data;
    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];
    
    /* inet_ntoaの結果を別々の文字列にコピー */
    strcpy(src_str, inet_ntoa(src_ip));
    strcpy(dst_str, inet_ntoa(dst_ip));
    
    printf("IP %s > %s: ICMP ", src_str, dst_str);
    
    /* ICMPタイプによって詳細表示を分岐 */
    switch(icmp_hdr->icmp_type) {
        case ICMP_ECHO:
            printf("echo request, id %d, seq %d, length %d",
                   ntohs(icmp_hdr->icmp_id), ntohs(icmp_hdr->icmp_seq), icmp_len);
            break;
            
        case ICMP_ECHOREPLY:
            printf("echo reply, id %d, seq %d, length %d", 
                   ntohs(icmp_hdr->icmp_id), ntohs(icmp_hdr->icmp_seq), icmp_len);
            break;
            
        case ICMP_UNREACH:
            printf("destination unreachable");
            switch(icmp_hdr->icmp_code) {
                case ICMP_UNREACH_NET:
                    printf(" (network unreachable)");
                    break;
                case ICMP_UNREACH_HOST:
                    printf(" (host unreachable)");
                    break;
                case ICMP_UNREACH_PROTOCOL:
                    printf(" (protocol unreachable)");
                    break;
                case ICMP_UNREACH_PORT:
                    printf(" (port unreachable)");
                    break;
                default:
                    printf(" (code %d)", icmp_hdr->icmp_code);
            }
            printf(", length %d", icmp_len);
            break;
            
        case ICMP_TIMXCEED:
            printf("time exceeded");
            if(icmp_hdr->icmp_code == ICMP_TIMXCEED_INTRANS) {
                printf(" (ttl exceeded in transit)");
            }
            printf(", length %d", icmp_len);
            break;
            
        case ICMP_REDIRECT:
            printf("redirect, length %d", icmp_len);
            break;
            
        default:
            printf("type %d code %d, length %d", 
                   icmp_hdr->icmp_type, icmp_hdr->icmp_code, icmp_len);
    }
    printf("\n");
}

//パケットの構造体へのヘッダ情報と生のポインタ
void
analyze(u_char *user, const struct pcap_pkthdr *pkhdr, const u_char *pktdata)
{
    static int cnt=0;                       //キャプチャのカウント
    struct ether_header *weh;               //パケットのヘッダ
    struct ip           *wih;               //ipヘッダ
    struct udphdr       *wuh;               //udpヘッダ
    uint16_t ep;                            //イーサネットフレームタイプ
    u_char   *p;                            //パケットデータのポインタ
    time_t now;
    struct tm *tm;
    char timestr[64];

    cnt++;
    p   = (u_char*) pktdata;
    weh = (struct ether_header*)pktdata;
    if(weh) {                               //イーサネットヘッダがあれば
        tm = localtime(&pkhdr->ts.tv_sec);
        strftime(timestr, sizeof(timestr), "%H:%M:%S", tm);
        printf("%s.%06lu ", timestr, (unsigned long)pkhdr->ts.tv_usec);
        ep  = ntohs(weh->ether_type);

        if(ep==ETHERTYPE_IP) {              //パケットタイプがIPの場合
            p += sizeof(struct ether_header);//イーサネットヘッダのサイズ分だけ進める
            wih = (struct ip*)p;            //ipヘッダの設定
            p += wih->ip_hl * 4;            //プロトコルヘッダに移動
            if(wih && wih->ip_p == IPPROTO_UDP) {
                wuh = (struct udphdr*)p;    //ポインタの設定
                if(wuh) {
                    printf("UDP sport %d dport %d\n",
                        ntohs(wuh->uh_sport), ntohs(wuh->uh_dport));//UDPヘッダ(wuh)から送信元ポートと宛先ポートを取り出して画面に表示する
                }
            }
            if(wih && wih->ip_p == IPPROTO_TCP){

            }
            if(wih && wih->ip_p == IPPROTO_ICMP){
                icmp(p, ntohs(wih->ip_len) - (wih->ip_hl * 4), wih->ip_src, wih->ip_dst);
            }

        }
        if(ep==ETHERTYPE_ARP){
            arp(p, pkhdr->caplen - sizeof(struct ether_header));
        }
        fflush(stdout);
    }
}

/*selectシステムコールを使用して待機するヘルパー関数*/
int
isreadable(int fd, int sec, int usec)
{
    fd_set fdset, rfdset;
    struct timeval timeout;
    struct timeval *ptimeout;
    int chk;
    FD_ZERO(&fdset);
    FD_SET(fd, &fdset);
    if(sec<0) { ptimeout = NULL; }
    else {
        ptimeout = &timeout;
        timeout.tv_sec  =  sec;
        if(usec<0) { timeout.tv_usec = 0; }
        else { timeout.tv_usec = usec; }
    }
retry:
    rfdset = fdset;
    chk = select(fd+1, &rfdset, NULL, NULL, ptimeout);
    if(chk<0) {
        if(errno==EINTR) { goto retry; }
        else {
            printf(" #isreadable:fd# %d, errno %d#\n",
                fd, errno);
            return -1;
        }
    }
    if(FD_ISSET(fd, &rfdset)) {
        return 1;
    }
    else {
        return 0;
    }
}

//isreadableを呼び出し、パケットが到着したらpcap_next_exでanalyzeに渡す
int
timerloop(pcap_t *phand, int waittime)
{
    struct pcap_pkthdr *pkthdr;
    u_char *pktdata;
    int     ck;
    int     fd;
    time_t  cur;
    time_t  limit;

    cur = time(NULL);
    limit = cur + waittime;

    fd = pcap_get_selectable_fd(phand);

    while(cur<limit) {
        if(isreadable(fd, 1, 0)) {
            ck = pcap_next_ex(phand, &pkthdr, (const u_char**)&pktdata);
            if(ck>0) {
                analyze(NULL, pkthdr, pktdata);
            }
        }
        cur = time(NULL);
    }
    return 0;
}

int
usage(char *pgn)
{
    printf("\
%s - PXE server\n\
usage:\n\
    %% %s [options]\n\
option:\n\
    -i dev      interface device\n\
example:\n\
    %% %s -i eth0\n\
\n\
", pgn, pgn, pgn);
    return 0;
}

int
main(int argc,char **argv)
{
    int    ik;
    char  *dev;
    pcap_if_t *ifp;
    char   errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* phand;
    struct bpf_program filter;
    bpf_u_int32 net;
    bpf_u_int32 netmask;
    int    flag;

    /* default values */
    ifp = NULL;
    dev = NULL;

    /*コマンドライン解釈*/
    while((flag=getopt(argc, argv, "hi:"))!=-1) {
        switch(flag) {
        case 'h':
            usage(argv[0]);
            exit(0);
            break;
        case 'i':
            dev = strdup(optarg);
            break;
        default:
            usage(argv[0]);
            exit(99);
        }
    }

#ifdef USE_PCAP_FINDALLDEVS
    ik = finddev(&dev, &ifp);
#else
    if(!dev) {
        dev = pcap_lookupdev(errbuf);
    }
#endif

    printf("device '%s' ifp %p\n", dev, ifp);
    if(!dev) {
        printf("no device name\n");
        exit(8);
    }
    if(pcap_lookupnet(dev, &net, &netmask, errbuf) == -1) {
        printf("pcap_lookupnet: %s\n", errbuf);
        exit(10);
    }
    printf("net H  %08llx\n", (long long)htonl(net));
    printf("mask H %08llx\n", (long long)htonl(netmask));

    /*パケットをキャプチャ(デバイス名,キャプチャサイズ,プロミスキャスモード,timeout,errorbuf)*/
    phand = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(phand == NULL) { 
        printf("pcap_open_live: %s\n",errbuf);
        exit(11);
    }
    if(pcap_compile(phand, &filter, "", 0, netmask) == -1) 
    {
        printf("printf calling pcap_compile");
        exit(12);
    }
    if(pcap_setfilter(phand, &filter) == -1) {
        printf("printf setting filter");
        exit(13);
    }

    timerloop(phand, 50);   //関数を呼び出す
    
    return 0;
}