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
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <sys/queue.h>

#define MAX_CONTENT_SIZE 4096
#define CONN_TIMEOUT 300

/* コネクション情報を保持する構造体 */
struct tcp_connection {
    struct in_addr src_ip;
    struct in_addr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    
    /* 統計情報 */
    uint32_t packets_sent;
    uint32_t packets_recv;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    
    /* コネクション状態 */
    time_t start_time;
    time_t last_activity;
    int is_active;  /* 1: active, 0: passive */
    int state;      /* TCP state tracking */
    
    /* 通信内容記録 */
    u_char content_sent[MAX_CONTENT_SIZE];
    u_char content_recv[MAX_CONTENT_SIZE];
    size_t content_sent_len;
    size_t content_recv_len;
    
    LIST_ENTRY(tcp_connection) entries;
};

LIST_HEAD(conn_list, tcp_connection) connections;

void print_connection_info(struct tcp_connection *conn);
void cleanup_old_connections(void);
void analyze_arp(const u_char *pktdata, int pktlen);
void analyze_icmp(const u_char *pktdata, int pktlen, struct in_addr src, struct in_addr dst);
void analyze_tcp(const u_char *pktdata, int pktlen, struct ip *ip_hdr);

/* コネクション検索用のヘルパー関数 */
struct tcp_connection *
find_connection(struct in_addr src_ip, uint16_t src_port,
                struct in_addr dst_ip, uint16_t dst_port)
{
    struct tcp_connection *conn;
    
    LIST_FOREACH(conn, &connections, entries) {
        if ((conn->src_ip.s_addr == src_ip.s_addr &&
             conn->src_port == src_port &&
             conn->dst_ip.s_addr == dst_ip.s_addr &&
             conn->dst_port == dst_port) ||
            (conn->src_ip.s_addr == dst_ip.s_addr &&
             conn->src_port == dst_port &&
             conn->dst_ip.s_addr == src_ip.s_addr &&
             conn->dst_port == src_port)) {
            return conn;
        }
    }
    return NULL;
}

/* タイムアウトしたコネクションのクリーンアップ */
void
cleanup_old_connections(void)
{
    struct tcp_connection *conn, *tmp;
    time_t now = time(NULL);
    
    for (conn = LIST_FIRST(&connections); conn != NULL; conn = tmp) {
        tmp = LIST_NEXT(conn, entries); // 次の要素を先に取得しておく
        if (now - conn->last_activity > CONN_TIMEOUT){
            printf("Connection timeout:\n");
            print_connection_info(conn);
            LIST_REMOVE(conn, entries);
            free(conn);
        }
    }
}

/* ARPパケットの解析 */
void
analyze_arp(const u_char *pktdata, int pktlen)
{
    struct ether_header *eth = (struct ether_header *)(pktdata - sizeof(struct ether_header));
    struct arphdr *arp = (struct arphdr *)pktdata;
    u_char *arp_data = (u_char *)(arp + 1);
    
    printf("ARP, ");
    
    if (ntohs(arp->ar_op) == ARPOP_REQUEST) {
        /* ARPリクエストの詳細表示 */
        struct in_addr spa, tpa;
        u_char *sha, *tha;
        
        sha = arp_data + 0;  /* Sender Hardware Address */
        memcpy(&spa, arp_data + 6, 4);  /* Sender Protocol Address */
        tha = arp_data + 10;  /* Target Hardware Address */
        memcpy(&tpa, arp_data + 14, 4);  /* Target Protocol Address */
        
        printf("Request who-has %s tell %s", inet_ntoa(tpa), inet_ntoa(spa));
        if (tha[0] || tha[1] || tha[2] || tha[3] || tha[4] || tha[5]) {
            printf(" (%02x:%02x:%02x:%02x:%02x:%02x)",
                   tha[0], tha[1], tha[2], tha[3], tha[4], tha[5]);
        }
    } else if (ntohs(arp->ar_op) == ARPOP_REPLY) {
        /* ARPリプライの詳細表示 */
        struct in_addr spa;
        u_char *sha;
        
        sha = arp_data + 0;
        memcpy(&spa, arp_data + 6, 4);
        
        printf("Reply %s is-at %02x:%02x:%02x:%02x:%02x:%02x",
               inet_ntoa(spa), sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]);
    }
    
    printf(", length %lu\n", (unsigned long)(pktlen + sizeof(struct ether_header)));
}

/* ICMPパケットの解析 */
void
analyze_icmp(const u_char *pktdata, int pktlen, struct in_addr src, struct in_addr dst)
{
    struct icmp *icmp_hdr = (struct icmp *)pktdata;
    char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
    
    strcpy(src_ip_str, inet_ntoa(src));
    strcpy(dst_ip_str, inet_ntoa(dst));
    
    printf("IP %s > %s: ICMP ", src_ip_str, dst_ip_str);
    
    switch(icmp_hdr->icmp_type) {
    case ICMP_ECHO:
        printf("echo request, id %d, seq %d", ntohs(icmp_hdr->icmp_id), ntohs(icmp_hdr->icmp_seq));
        break;
    case ICMP_ECHOREPLY:
        printf("echo reply, id %d, seq %d", ntohs(icmp_hdr->icmp_id), ntohs(icmp_hdr->icmp_seq));
        break;
    case ICMP_UNREACH:
        printf("destination unreachable");
        break;
    default:
        printf("type %d", icmp_hdr->icmp_type);
    }
    
    printf(", length %d\n", pktlen);
}


/* TCPパケットの解析と記録 */
void
analyze_tcp(const u_char *pktdata, int pktlen, struct ip *ip_hdr)
{
    struct tcphdr *tcp_hdr = (struct tcphdr *)pktdata;
    struct tcp_connection *conn;
    const u_char *payload;
    int payload_len;
    int is_from_src;
    char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];

    strcpy(src_ip_str, inet_ntoa(ip_hdr->ip_src));
    strcpy(dst_ip_str, inet_ntoa(ip_hdr->ip_dst));
    
    printf("IP %s.%d > %s.%d: Flags [",
           src_ip_str, ntohs(tcp_hdr->th_sport),
           dst_ip_str, ntohs(tcp_hdr->th_dport));
    
    /* TCPフラグの表示 */
    if (tcp_hdr->th_flags & TH_SYN) printf("S");
    if (tcp_hdr->th_flags & TH_FIN) printf("F");
    if (tcp_hdr->th_flags & TH_RST) printf("R");
    if (tcp_hdr->th_flags & TH_PUSH) printf("P");
    if (tcp_hdr->th_flags & TH_ACK) printf(".");
    
    /* No flags set */
    if (!(tcp_hdr->th_flags & (TH_SYN|TH_FIN|TH_RST|TH_PUSH|TH_ACK))) {
        printf("none");
    }

    printf("], ");
    
    /* Payload length */
    payload_len = pktlen - (tcp_hdr->th_off * 4);
    
    /* SYN or FIN packets show absolute sequence numbers */
    if (tcp_hdr->th_flags & (TH_SYN|TH_FIN)) {
        printf("seq %u", ntohl(tcp_hdr->th_seq));
        if (tcp_hdr->th_flags & TH_ACK) {
            printf(", ack %u", ntohl(tcp_hdr->th_ack));
        }
    } else if (payload_len > 0) {
        /* Data packets show relative sequence numbers */
        printf("seq %u:%u, ack %u", 
               ntohl(tcp_hdr->th_seq) - 1, 
               ntohl(tcp_hdr->th_seq) + payload_len - 1,
               ntohl(tcp_hdr->th_ack));
    } else {
        /* ACK only packets */
        printf("ack %u", ntohl(tcp_hdr->th_ack));
    }

    /* Additional information for certain packets */
    if (tcp_hdr->th_flags & TH_SYN) {
        printf(", win %d", ntohs(tcp_hdr->th_win));
        /* Options could be parsed here if needed */
        printf(", options [...]");
    }
    
    printf(", length %d", payload_len);
    
    /* Check for HTTP content */
    if (payload_len > 0) {
        payload = pktdata + (tcp_hdr->th_off * 4);
        if (payload_len >= 4) {
            if (strncmp((char*)payload, "GET ", 4) == 0 ||
                strncmp((char*)payload, "POST", 4) == 0 ||
                strncmp((char*)payload, "HTTP", 4) == 0) {
                printf(": HTTP");
                /* Print first part of HTTP request/response */
                if (strncmp((char*)payload, "GET ", 4) == 0) {
                    char *end = memchr(payload, '\r', payload_len);
                    if (end) {
                        int len = end - (char*)payload;
                        if (len > 50) len = 50;
                        printf(": %.*s", len, payload);
                    }
                } else if (strncmp((char*)payload, "HTTP", 4) == 0) {
                    char *end = memchr(payload, '\r', payload_len);
                    if (end) {
                        int len = end - (char*)payload;
                        if (len > 30) len = 30;
                        printf(": %.*s", len, payload);
                    }
                }
            }
        }
    }
    
    printf("\n");


    /* コネクション管理 */
    conn = find_connection(ip_hdr->ip_src, tcp_hdr->th_sport,
                          ip_hdr->ip_dst, tcp_hdr->th_dport);
    
    /* 新規コネクション */
    if (!conn && (tcp_hdr->th_flags & TH_SYN)) {
        conn = calloc(1, sizeof(struct tcp_connection));
        if (conn) {
            conn->src_ip = ip_hdr->ip_src;
            conn->dst_ip = ip_hdr->ip_dst;
            conn->src_port = tcp_hdr->th_sport;
            conn->dst_port = tcp_hdr->th_dport;
            conn->start_time = time(NULL);
            conn->last_activity = conn->start_time;
            conn->is_active = !(tcp_hdr->th_flags & TH_ACK);
            LIST_INSERT_HEAD(&connections, conn, entries);
        }
    }
    
    if (conn) {
        conn->last_activity = time(NULL);
        
        /* 方向の判定 */
        is_from_src = (ip_hdr->ip_src.s_addr == conn->src_ip.s_addr &&
                       tcp_hdr->th_sport == conn->src_port);
        
        /* 統計情報の更新 */
        if (is_from_src) {
            conn->packets_sent++;
            conn->bytes_sent += ntohs(ip_hdr->ip_len);
        } else {
            conn->packets_recv++;
            conn->bytes_recv += ntohs(ip_hdr->ip_len);
        }
        
        /* ペイロードの記録 */
        payload_len = pktlen - (tcp_hdr->th_off * 4);
        if (payload_len > 0) {
            payload = pktdata + (tcp_hdr->th_off * 4);
            
            if (is_from_src) {
                size_t space = MAX_CONTENT_SIZE - conn->content_sent_len;
                size_t to_copy = (payload_len < space) ? payload_len : space;
                if (to_copy > 0) {
                    memcpy(conn->content_sent + conn->content_sent_len,
                           payload, to_copy);
                    conn->content_sent_len += to_copy;
                }
            } else {
                size_t space = MAX_CONTENT_SIZE - conn->content_recv_len;
                size_t to_copy = (payload_len < space) ? payload_len : space;
                if (to_copy > 0) {
                    memcpy(conn->content_recv + conn->content_recv_len,
                           payload, to_copy);
                    conn->content_recv_len += to_copy;
                }
            }
        }
        
        /* コネクション終了の検出 */
        if (tcp_hdr->th_flags & (TH_FIN | TH_RST)) {
            print_connection_info(conn);
            LIST_REMOVE(conn, entries);
            free(conn);
        }
    }
}

/* コネクション情報の表示 */
void
print_connection_info(struct tcp_connection *conn)
{
    char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
    
    strcpy(src_ip_str, inet_ntoa(conn->src_ip));
    strcpy(dst_ip_str, inet_ntoa(conn->dst_ip));

    printf("\n=== TCP Connection Summary ===\n");
    printf("Connection: %s:%d <-> %s:%d\n",
           src_ip_str, ntohs(conn->src_port),
           dst_ip_str, ntohs(conn->dst_port));
    printf("Type: %s\n", conn->is_active ? "Active" : "Passive");
    printf("Duration: %ld seconds\n", time(NULL) - conn->start_time);
    printf("Packets: sent=%u, recv=%u\n", conn->packets_sent, conn->packets_recv);
    printf("Bytes: sent=%llu, recv=%llu\n", 
           (unsigned long long)conn->bytes_sent,
           (unsigned long long)conn->bytes_recv);
    
    printf("\n--- Content Sent (first %zu bytes) ---\n", conn->content_sent_len);
    fwrite(conn->content_sent, 1, conn->content_sent_len, stdout);
    
    printf("\n--- Content Received (first %zu bytes) ---\n", conn->content_recv_len);
    fwrite(conn->content_recv, 1, conn->content_recv_len, stdout);
    printf("\n=============================\n\n");
}


#ifdef USE_PCAP_FINDALLDEVS
int
finddev(char **xdev, pcap_if_t  **xifp)
{
    char       errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *list;
    pcap_if_t *u;
    int        ik;
    char      *dev;
    pcap_if_t *ifp;

    dev = *xdev;
    ifp = *xifp;

    ik = pcap_findalldevs(&list, errbuf);
    if(ik) {
        perror("pcap_findalldevs");
        exit(91);
    }
    u = list;
    while(u) {
        if(u->flags & PCAP_IF_UP) {
            if(dev && strcmp(dev, u->name) == 0) {
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

    pcap_freealldevs(list);

    return 0;
}
#endif

struct box {
    pcap_t *hand;
};

/* パケット解析関数 */
void
analyze(u_char *user, const struct pcap_pkthdr *pkhdr, const u_char *pktdata)
{
    static int cnt=0;
    static time_t last_cleanup = 0;
    struct ether_header *eth_hdr;
    struct ip *ip_hdr;
    uint16_t ether_type;
    const u_char *p;
    time_t now;
    struct tm *tm;
    char timestr[64];
    
    cnt++;
    
    /* 定期的なクリーンアップ */
    now = time(NULL);
    if (now - last_cleanup > 10) {
        cleanup_old_connections();
        last_cleanup = now;
    }
    
    /* タイムスタンプ表示 (HH:MM:SS.microseconds) */
    tm = localtime(&pkhdr->ts.tv_sec);
    strftime(timestr, sizeof(timestr), "%H:%M:%S", tm);
    printf("%s.%06lu ", timestr, (unsigned long)pkhdr->ts.tv_usec);
    
    p = pktdata;
    eth_hdr = (struct ether_header *)pktdata;
    
    if (!eth_hdr) return;
    
    ether_type = ntohs(eth_hdr->ether_type);
    p += sizeof(struct ether_header);
    
    switch (ether_type) {
    case ETHERTYPE_IP:
        ip_hdr = (struct ip *)p;
        
        p += ip_hdr->ip_hl * 4;
        
        switch (ip_hdr->ip_p) {
        case IPPROTO_TCP:
            analyze_tcp(p, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4), ip_hdr);
            break;
            
        case IPPROTO_UDP:
        {
        struct udphdr *udp_hdr = (struct udphdr *)p;
        char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
        strcpy(src_str, inet_ntoa(ip_hdr->ip_src));
        strcpy(dst_str, inet_ntoa(ip_hdr->ip_dst));
        printf("IP %s.%d > %s.%d: UDP, length %d\n",
               src_str, ntohs(udp_hdr->uh_sport),
               dst_str, ntohs(udp_hdr->uh_dport),
               (int)(ntohs(udp_hdr->uh_ulen) - sizeof(struct udphdr)));
        }
        break;
            
        case IPPROTO_ICMP:
            analyze_icmp(p, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4),
                        ip_hdr->ip_src, ip_hdr->ip_dst);
            break;
            
        default:
            printf("IP %s > %s: Protocol %d\n", 
                   inet_ntoa(ip_hdr->ip_src), inet_ntoa(ip_hdr->ip_dst), ip_hdr->ip_p);
        }
        break;
        
    case ETHERTYPE_ARP:
        analyze_arp(p, pkhdr->caplen - sizeof(struct ether_header));
        break;
        
    default:
        printf("Unknown ethernet type 0x%04x\n", ether_type);
    }
    
    fflush(stdout);
}

int
mainloop(pcap_t *phand)
{
    struct pcap_pkthdr *pkthdr;
    u_char *pktdata;
    int     ck;

    while(1) {
        ck = pcap_next_ex(phand, &pkthdr, (const u_char**)&pktdata);
        if(ck>0) {
            analyze(NULL, pkthdr, pktdata);
        }
    }
    return 0;
}

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
%s - Network packet analyzer (tcpdump-like)\n\
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

    LIST_INIT(&connections);

    /* default values */
    ifp = NULL;
    dev = NULL;

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

    /* バッファサイズを明示的に設定、プロミスキャスモード有効、タイムアウト10ms */
    phand = pcap_open_live(dev, 65535, 1, 10, errbuf);
    if(phand == NULL) { 
        printf("pcap_open_live: %s\n",errbuf);
        exit(11);
    }
    
    /* すべてのパケットをキャプチャ */
    if(pcap_compile(phand, &filter, "", 0, netmask) == -1) 
    {
        printf("Error calling pcap_compile: %s\n", pcap_geterr(phand));
        exit(12);
    }
    
    if(pcap_setfilter(phand, &filter) == -1) {
        printf("Error setting filter: %s\n", pcap_geterr(phand));
        exit(13);
    }

    printf("Starting packet capture...\n");
    printf("Press Ctrl+C to stop\n\n");
    
    /* 無限ループでパケットキャプチャ */
    mainloop(phand);
    
    return 0;
}