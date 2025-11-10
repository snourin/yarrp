/****************************************************************************
   Program:     $Id: listener.cpp 40 2016-01-02 18:54:39Z rbeverly $
   Date:        $Date: 2016-01-02 10:54:39 -0800 (Sat, 02 Jan 2016) $
   Description: yarrp listener thread
****************************************************************************/
#include "yarrp.h"
#include <signal.h>

static volatile bool run = true;
void intHandler(int dummy);

#ifndef _LINUX
int bpfinit(char *dev, size_t *bpflen) {
    int rcvsock = -1;

    debug(DEVELOP, ">> Listener6 BPF");
    rcvsock = bpfget();
    if (rcvsock < 0) fatal("bpf open error\n");
    struct ifreq bound_if;
    strcpy(bound_if.ifr_name, dev);
    if (ioctl(rcvsock, BIOCSETIF, &bound_if) > 0) fatal("ioctl err\n");
    uint32_t enable = 1;
    if (ioctl(rcvsock, BIOCSHDRCMPLT, &enable) <0) fatal("ioctl err\n");
    if (ioctl(rcvsock, BIOCIMMEDIATE, &enable) <0) fatal("ioctl err\n");
    struct bpf_program fcode = {0};
    struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IPV6, 0, 3),
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 20),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_ICMPV6, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, (u_int)-1),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };
    fcode.bf_len = sizeof(insns) / sizeof(struct bpf_insn);
    fcode.bf_insns = &insns[0];
    if(ioctl(rcvsock, BIOCSETF, &fcode) < 0) fatal("set filter\n");
    ioctl(rcvsock, BIOCGBLEN, bpflen);
    return rcvsock;
}
#endif

void stop_listener6() {
    run = false;
}

void *listener6(void *args) {
    fd_set rfds;
    Traceroute6 *trace = reinterpret_cast < Traceroute6 * >(args);
    struct timeval timeout;
    unsigned char *buf = (unsigned char *) calloc(1,PKTSIZE);
    uint32_t nullreads = 0;
    int n, len;
    TTLHisto *ttlhisto = NULL;
    uint32_t elapsed = 0;
    struct ip6_hdr *ip = NULL;                /* IPv6 hdr */
    struct icmp6_hdr *ippayload = NULL;       /* ICMP6 hdr */
    int rcvsock;                              /* receive (icmp) socket file descriptor */
#ifdef _LINUX
    int tcpsock; /* receive tcp socket file descriptor */
#endif    

    /* block until main thread says we're ready. */
    trace->lock(); 
    trace->unlock(); 

#ifdef _LINUX
    if ((rcvsock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        cerr << "yarrp listener socket error:" << strerror(errno) << endl;
    }

    /* bind PF_PACKET to single interface */
    struct ifreq ifr;
    if (trace->config->int_name_listener) {
        strncpy(ifr.ifr_name, trace->config->int_name_listener, IFNAMSIZ);
    }
    else{
        strncpy(ifr.ifr_name, trace->config->int_name, IFNAMSIZ);
    }
    if (ioctl(rcvsock, SIOCGIFINDEX, &ifr) < 0) fatal ("ioctl err");;
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = PF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifr.ifr_ifindex;
    if (bind(rcvsock, (struct sockaddr*) &sll, sizeof(sll)) < 0) {
        fatal("Bind to PF_PACKET socket");
    }

    if ((tcpsock = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP)) < 0) {
        cerr << "yarrp TCP6 socket error: " << strerror(errno) << endl;
    }
#else
    /* Init BPF */
    size_t blen = 0;
    if (trace->config->int_name_listener) {
        rcvsock = bpfinit(trace->config->int_name_listener, &blen);
    } else {
        rcvsock = bpfinit(trace->config->int_name, &blen);
    }
    unsigned char *bpfbuf = (unsigned char *) calloc(1,blen);
    struct bpf_hdr *bh = NULL;
#endif

    signal(SIGINT, intHandler);
    while (run) {
        // if (nullreads >= MAXNULLREADS)
        //     break;
#ifdef _LINUX
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        FD_ZERO(&rfds);
        FD_SET(rcvsock, &rfds);
        FD_SET(tcpsock, &rfds);
        int maxfd = max(rcvsock, tcpsock);
        n = select(maxfd + 1, &rfds, NULL, NULL, &timeout);
        if (n == 0) {
            nullreads++;
            cerr << ">> Listener: timeout " << nullreads;
            cerr << "/" << MAXNULLREADS << endl;
            continue;
        }
	if (n == -1) {
            fatal("select error");
        }
        nullreads = 0;
        memset(buf, 0, PKTSIZE);

        if (FD_ISSET(rcvsock, &rfds)) {
            len = recv(rcvsock, buf, PKTSIZE, 0); 
        } else if (FD_ISSET(tcpsock, &rfds)) {
            len = recv(tcpsock, buf, PKTSIZE, 0);
        }
#else
        memset(bpfbuf, 0, blen);
        len = read(rcvsock, bpfbuf, blen);
        unsigned char *p = bpfbuf;
reloop:
        bh = (struct bpf_hdr *)p;
        buf = p + bh->bh_hdrlen;  /* realign buf */
#endif
        if (len == -1) {
            fatal("%s %s", __func__, strerror(errno));
        }

        unsigned char *bufptr = buf; 
        // Check if there is an Ethernet header
        if ((bufptr[0] & 0xF0) != 0x60) {
            bufptr += ETH_HDRLEN ;
        }
        ip = (struct ip6_hdr *)(bufptr);
        if (ip->ip6_nxt == IPPROTO_ICMPV6) {
            ippayload = (struct icmp6_hdr *)&bufptr[sizeof(struct ip6_hdr)];
            elapsed = trace->elapsed();
            if ( (ippayload->icmp6_type == ICMP6_TIME_EXCEEDED) or
                 (ippayload->icmp6_type == ICMP6_DST_UNREACH) or
                 (ippayload->icmp6_type == ICMP6_ECHO_REPLY) ) {
                ICMP *icmp = new ICMP6(ip, ippayload, elapsed, trace->config->coarse, trace->config);
                if (icmp->is_yarrp) {
                    if (verbosity > LOW)
                        icmp->print();
                    // if (icmp->getInstance() != trace->config->instance) {
                    //     if (verbosity > HIGH) {
                    //         cerr << ">> Listener: packet instance mismatch." << endl;
                    //     }
                    //     delete icmp;
                    //     continue;
                    // }
                    /* Fill mode logic. */
                    if (trace->config->fillmode) {
                        if ( (icmp->getTTL() >= trace->config->maxttl) and
                          (icmp->getTTL() < trace->config->fillmode) ) {
                         trace->stats->fills+=1;
                         trace->probe(icmp->quoteDst6(), icmp->getTTL() + 1); 
                        }
                    }
                    icmp->write(&(trace->config->out), trace->stats->count);
                    /* TTL tree histogram */
                    if (trace->ttlhisto.size() > icmp->quoteTTL()) {
                     ttlhisto = trace->ttlhisto[icmp->quoteTTL()];
                     ttlhisto->add(icmp->getSrc6(), elapsed);
                    }
                    if (verbosity > DEBUG)
                     trace->dumpHisto();
                }
                delete icmp;
            }
        } else if (ip->ip6_nxt == IPPROTO_TCP) {
            struct tcphdr *tcp_hdr = (struct tcphdr *) (bufptr + sizeof(struct ip6_hdr)); 
            TCP6 *tcp = new TCP6(ip, tcp_hdr, trace->config->instance);
            TCP6 *tcp6 = static_cast<TCP6 *>(tcp);
            Traceroute6 *trace6 = static_cast<Traceroute6 *>(trace);

            if (tcp6->fromYarrp()) {
                tcp->write(&(trace->config->tcp_out));
            }

            delete tcp;
        }
#ifndef _LINUX
	p += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
	if (p < bpfbuf + len) goto reloop;
#endif
    }
    return NULL;
}
