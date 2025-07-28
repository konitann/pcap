/*
 * if use recently libpcap, set USE_PCAP_FINDALLDEVS like following:
 * $ cc -DUSE_PCAP_FINDALLDEVS foo.c -lpcap
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
#include <netinet/tcp.h> 

#define DATA_BUFFER_SIZE 4096 
#define CONNECTION_TIMEOUT 300

struct flow_data {
    uint64_t packets;
    uint64_t bytes;
    unsigned char buffer[DATA_BUFFER_SIZE];
    size_t buffer_len;
};

struct tcp_connection {
    struct in_addr ip1;
    struct in_addr ip2;
    uint16_t port1;
    uint16_t port2;

    struct flow_data flow1_to_2; 
    struct flow_data flow2_to_1; 

    time_t last_packet_time; 
    int fin_received;        

    struct tcp_connection *next; 
};

struct tcp_connection *connection_list = NULL;


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

void udp(const u_char *udp_data, int total_len, struct in_addr src_ip, struct in_addr dst_ip)
{
    struct udphdr *udp_hdr = (struct udphdr *)udp_data;
    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];
    int udp_len;
    int data_len;
    
    strcpy(src_str, inet_ntoa(src_ip));
    strcpy(dst_str, inet_ntoa(dst_ip));
    
    udp_len = ntohs(udp_hdr->uh_ulen);
    data_len = udp_len - sizeof(struct udphdr);
    
    printf("IP %s.%d > %s.%d: UDP, length %d",
           src_str, ntohs(udp_hdr->uh_sport),
           dst_str, ntohs(udp_hdr->uh_dport),
           data_len);
    
    if (ntohs(udp_hdr->uh_dport) == 53 || ntohs(udp_hdr->uh_sport) == 53) {
        printf(" (DNS)");
    } else if (ntohs(udp_hdr->uh_dport) == 67 || ntohs(udp_hdr->uh_sport) == 67 ||
               ntohs(udp_hdr->uh_dport) == 68 || ntohs(udp_hdr->uh_sport) == 68) {
        printf(" (DHCP)");
    } else if (ntohs(udp_hdr->uh_dport) == 123 || ntohs(udp_hdr->uh_sport) == 123) {
        printf(" (NTP)");
    } else if (ntohs(udp_hdr->uh_dport) == 161 || ntohs(udp_hdr->uh_sport) == 161 ||
               ntohs(udp_hdr->uh_dport) == 162 || ntohs(udp_hdr->uh_sport) == 162) {
        printf(" (SNMP)");
    } else if (ntohs(udp_hdr->uh_dport) == 514 || ntohs(udp_hdr->uh_sport) == 514) {
        printf(" (syslog)");
    } else if ((ntohs(udp_hdr->uh_dport) >= 5060 && ntohs(udp_hdr->uh_dport) <= 5061) ||
               (ntohs(udp_hdr->uh_sport) >= 5060 && ntohs(udp_hdr->uh_sport) <= 5061)) {
        printf(" (SIP)");
    }
    
    printf("\n");
}

void print_payload(const unsigned char *payload, int len) {
    int i;
    const int line_width = 16;

    for (i = 0; i < len; i++) {
        if (i % line_width == 0) {
            printf("    %04x: ", i);
        }
        printf("%02x ", payload[i]);
        if (i % line_width == line_width - 1 || i == len - 1) {
            for (int j = 0; j < line_width - 1 - (i % line_width); j++) {
                printf("   ");
            }
            printf("| ");
            for (int j = i - (i % line_width); j <= i; j++) {
                if (payload[j] >= 32 && payload[j] <= 126) {
                    printf("%c", payload[j]);
                } else {
                    printf(".");
                }
            }
            printf("\n");
        }
    }
}

void print_and_free_connection(struct tcp_connection *conn, const char *reason) {
    char ip1_str[INET_ADDRSTRLEN], ip2_str[INET_ADDRSTRLEN];
    strcpy(ip1_str, inet_ntoa(conn->ip1));
    strcpy(ip2_str, inet_ntoa(conn->ip2));

    printf("\n------------------------------------------------------------\n");
    printf("TCP Connection Closed (%s)\n", reason);
    printf("  %s:%d <-> %s:%d\n", ip1_str, ntohs(conn->port1), ip2_str, ntohs(conn->port2));
    printf("\n");
    printf("  Flow: %s:%d -> %s:%d\n", ip1_str, ntohs(conn->port1), ip2_str, ntohs(conn->port2));
    printf("    Packets: %lu\n", conn->flow1_to_2.packets);
    printf("    Bytes: %lu\n", conn->flow1_to_2.bytes);
    if (conn->flow1_to_2.buffer_len > 0) {
        printf("    Data (%zu bytes):\n", conn->flow1_to_2.buffer_len);
        print_payload(conn->flow1_to_2.buffer, conn->flow1_to_2.buffer_len);
    }
    printf("\n");
    printf("  Flow: %s:%d -> %s:%d\n", ip2_str, ntohs(conn->port2), ip1_str, ntohs(conn->port1));
    printf("    Packets: %lu\n", conn->flow2_to_1.packets);
    printf("    Bytes: %lu\n", conn->flow2_to_1.bytes);
     if (conn->flow2_to_1.buffer_len > 0) {
        printf("    Data (%zu bytes):\n", conn->flow2_to_1.buffer_len);
        print_payload(conn->flow2_to_1.buffer, conn->flow2_to_1.buffer_len);
    }
    printf("------------------------------------------------------------\n\n");
    fflush(stdout);

    // リストから削除
    if (connection_list == conn) {
        connection_list = conn->next;
    } else {
        struct tcp_connection *curr = connection_list;
        while (curr && curr->next != conn) {
            curr = curr->next;
        }
        if (curr) {
            curr->next = conn->next;
        }
    }
    free(conn);
}

void check_timeout_connections() {
    time_t now = time(NULL);
    struct tcp_connection *curr = connection_list;
    struct tcp_connection *next = NULL;

    while (curr) {
        // 現在の要素を解放する可能性があるので、先に次の要素を保持しておく
        next = curr->next;
        if (now - curr->last_packet_time > CONNECTION_TIMEOUT) {
            print_and_free_connection(curr, "Timeout");
        }
        curr = next;
    }
}

const char* format_tcp_flags(uint8_t flags) {
    static char flag_str[10];
    memset(flag_str, 0, sizeof(flag_str));
    strcat(flag_str, "[");
    if (flags & TH_SYN) strcat(flag_str, "S");
    if (flags & TH_FIN) strcat(flag_str, "F");
    if (flags & TH_RST) strcat(flag_str, "R");
    if (flags & TH_PUSH) strcat(flag_str, "P");
    if (flags & TH_ACK) strcat(flag_str, "."); // ACKはドットで表現
    strcat(flag_str, "]");
    return flag_str;
}


void tcp(const u_char *data, int total_len, struct in_addr src_ip, struct in_addr dst_ip) {
    struct tcphdr *tcp_hdr = (struct tcphdr *)data;
    uint16_t src_port = tcp_hdr->th_sport;
    uint16_t dst_port = tcp_hdr->th_dport;
    int tcp_hdr_len = tcp_hdr->th_off * 4;
    int payload_len = total_len - tcp_hdr_len;

    // ★★ ここから追加: tcpdump風のリアルタイム出力 ★★
    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];
    strcpy(src_str, inet_ntoa(src_ip));
    strcpy(dst_str, inet_ntoa(dst_ip));

    printf("IP %s.%d > %s.%d: Flags %s, seq %u",
           src_str, ntohs(src_port),
           dst_str, ntohs(dst_port),
           format_tcp_flags(tcp_hdr->th_flags),
           ntohl(tcp_hdr->th_seq));

    // ACKフラグが立っている場合のみack番号を表示
    if (tcp_hdr->th_flags & TH_ACK) {
        printf(", ack %u", ntohl(tcp_hdr->th_ack));
    }

    printf(", win %u, length %d\n",
           ntohs(tcp_hdr->th_win),
           payload_len);
    // ★★ ここまで追加 ★★


    // ▼▼ 以下、既存のコネクション追跡・サマリー機能はそのまま維持 ▼▼
    struct tcp_connection *conn = NULL;
    struct tcp_connection *curr = connection_list;

    // 既存コネクションを検索
    while (curr) {
        if ((curr->ip1.s_addr == src_ip.s_addr && curr->port1 == src_port &&
             curr->ip2.s_addr == dst_ip.s_addr && curr->port2 == dst_port) ||
            (curr->ip1.s_addr == dst_ip.s_addr && curr->port1 == dst_port &&
             curr->ip2.s_addr == src_ip.s_addr && curr->port2 == src_port)) {
            conn = curr;
            break;
        }
        curr = curr->next;
    }

    // 新規コネクション (SYNパケット)
    if (!conn && (tcp_hdr->th_flags & TH_SYN) && !(tcp_hdr->th_flags & TH_ACK)) {
        conn = (struct tcp_connection *)malloc(sizeof(struct tcp_connection));
        if (!conn) {
            perror("malloc for new connection failed");
            return;
        }
        memset(conn, 0, sizeof(struct tcp_connection));

        if (ntohl(src_ip.s_addr) < ntohl(dst_ip.s_addr)) {
            conn->ip1 = src_ip;
            conn->port1 = src_port;
            conn->ip2 = dst_ip;
            conn->port2 = dst_port;
        } else {
            conn->ip1 = dst_ip;
            conn->port1 = dst_port;
            conn->ip2 = src_ip;
            conn->port2 = src_port;
        }
        conn->last_packet_time = time(NULL);
        
        conn->next = connection_list;
        connection_list = conn;
    }

    if (conn) {
        conn->last_packet_time = time(NULL);
        struct flow_data *flow = NULL;

        if (conn->ip1.s_addr == src_ip.s_addr && conn->port1 == src_port) {
            flow = &conn->flow1_to_2;
        } else {
            flow = &conn->flow2_to_1;
        }

        flow->packets++;
        flow->bytes += payload_len;

        if (payload_len > 0 && flow->buffer_len < DATA_BUFFER_SIZE) {
            int copy_len = payload_len;
            if (flow->buffer_len + copy_len > DATA_BUFFER_SIZE) {
                copy_len = DATA_BUFFER_SIZE - flow->buffer_len;
            }
            memcpy(flow->buffer + flow->buffer_len, data + tcp_hdr_len, copy_len);
            flow->buffer_len += copy_len;
        }

        if (tcp_hdr->th_flags & TH_RST) {
            print_and_free_connection(conn, "RST");
        } else if (tcp_hdr->th_flags & TH_FIN) {
            if(conn->fin_received){
                print_and_free_connection(conn, "FIN");
            } else {
                conn->fin_received = 1;
            }
        }
    }
}


//パケットの構造体へのヘッダ情報と生のポインタ
void
analyze(u_char *user, const struct pcap_pkthdr *pkhdr, const u_char *pktdata)
{
    static int cnt=0;                       //キャプチャのカウント
    struct ether_header *weh;               //パケットのヘッダ
    struct ip           *wih;               //ipヘッダ
    uint16_t ep;                            //イーサネットフレームタイプ
    u_char   *p;                            //パケットデータのポインタ
    time_t now;
    struct tm *tm;
    char timestr[64];

    cnt++;
    p   = (u_char*) pktdata;
    weh = (struct ether_header*)pktdata;
    if(weh) {                               //イーサネットヘッダがあれば
        ep  = ntohs(weh->ether_type);

        if(ep==ETHERTYPE_IP) {              //パケットタイプがIPの場合
            p += sizeof(struct ether_header);//イーサネットヘッダのサイズ分だけ進める
            wih = (struct ip*)p;            //ipヘッダの設定
            
            tm = localtime(&pkhdr->ts.tv_sec);
            strftime(timestr, sizeof(timestr), "%H:%M:%S", tm);
            printf("%s.%06lu ", timestr, (unsigned long)pkhdr->ts.tv_usec);

            int ip_hdr_len = wih->ip_hl * 4;
            p += ip_hdr_len;            //プロトコルヘッダに移動

            if(wih && wih->ip_p == IPPROTO_UDP) {
                udp(p, ntohs(wih->ip_len) - ip_hdr_len, wih->ip_src, wih->ip_dst);
            }
            if(wih && wih->ip_p == IPPROTO_TCP){
                tcp(p, ntohs(wih->ip_len) - ip_hdr_len, wih->ip_src, wih->ip_dst);
            }
            if(wih && wih->ip_p == IPPROTO_ICMP){
                icmp(p, ntohs(wih->ip_len) - ip_hdr_len, wih->ip_src, wih->ip_dst);
            }

        }
        if(ep==ETHERTYPE_ARP){
            tm = localtime(&pkhdr->ts.tv_sec);
            strftime(timestr, sizeof(timestr), "%H:%M:%S", tm);
            printf("%s.%06lu ", timestr, (unsigned long)pkhdr->ts.tv_usec);
            arp(p, pkhdr->caplen); 
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
    time_t  last_check_time = time(NULL);

    fd = pcap_get_selectable_fd(phand);

    while(1) { 
        if(isreadable(fd, 1, 0)) { 
            ck = pcap_next_ex(phand, &pkthdr, (const u_char**)&pktdata);
            if(ck > 0) {
                analyze(NULL, pkthdr, pktdata);
            }
        }
        if (time(NULL) - last_check_time >= 1) {
            check_timeout_connections();
            last_check_time = time(NULL);
        }
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
    printf("net: %s, ", inet_ntoa(*(struct in_addr *)&net));
    printf("netmask: %s\n", inet_ntoa(*(struct in_addr *)&netmask));

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

    printf("Start capturing.\n");
    timerloop(phand, -1);  
    
    while (connection_list) {
        print_and_free_connection(connection_list, "Shutdown");
    }
    
    pcap_close(phand);
    return 0;
}