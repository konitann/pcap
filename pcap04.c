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

void
analyze(u_char *user, const struct pcap_pkthdr *pkhdr, const u_char *pktdata)
{
    static int cnt=0;
    struct ether_header *weh;
    struct ip           *wih;
    struct udphdr       *wuh;
    uint16_t ep;
    u_char   *p;

    cnt++;
    p   = (u_char*) pktdata;
    weh = (struct ether_header*)pktdata;
    if(weh) {
        ep  = ntohs(weh->ether_type);
        if(ep==ETHERTYPE_IP) {
            p += sizeof(struct ether_header);
            wih = (struct ip*)p;
            p += wih->ip_hl * 4;
            if(wih && wih->ip_p == IPPROTO_UDP) {
                wuh = (struct udphdr*)p;
                if(wuh) {
                    printf("UDP sport %d dport %d\n",
                        ntohs(wuh->uh_sport), ntohs(wuh->uh_dport));
                }
            }
        }
        fflush(stdout);
    }
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

    timerloop(phand, 50);
    
    return 0;
}