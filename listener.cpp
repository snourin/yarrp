/****************************************************************************
   Program:     $Id: listener.cpp 40 2016-01-02 18:54:39Z rbeverly $
   Date:        $Date: 2016-01-02 10:54:39 -0800 (Sat, 02 Jan 2016) $
   Description: yarrp listener thread
****************************************************************************/
#include "yarrp.h"
#include <thread>
#include <signal.h>

static volatile bool run = true;
extern volatile bool startTimeout;

void intHandler(int dummy) {
    run = false;
}

void           *
icmpListener(void *args) {
    fd_set rfds;
    Traceroute *trace = reinterpret_cast < Traceroute * >(args);
    struct timeval timeout;
    unsigned char buf[PKTSIZE];
    uint32_t nullreads = 0;
    int n, len;
    TTLHisto *ttlhisto = NULL;
    uint32_t elapsed = 0;
    struct ip *ip = NULL;
    struct icmp *ippayload = NULL;
    int rcvsock; /* receive (icmp) socket file descriptor */

    /* block until main thread says we're ready. */
    trace->lock(); 
    trace->unlock(); 

    if ((rcvsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        cerr << "yarrp listener socket error:" << strerror(errno) << endl;
    }

    while (true) {
        if (nullreads >= MAXNULLREADS)
            break;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        FD_ZERO(&rfds);
        FD_SET(rcvsock, &rfds);
        n = select(rcvsock + 1, &rfds, NULL, NULL, &timeout);
        /* only timeout if we're also probing (not listen-only mode) */
        if (startTimeout &&  (n == 0) and (trace->config->probe)) {
            nullreads++;
            cerr << ">> Listener: timeout " << nullreads;
            cerr << "/" << MAXNULLREADS << endl;
            continue;
        }
        if (n > 0) {
            nullreads = 0;
            memset(buf, 0, PKTSIZE);
            len = recv(rcvsock, buf, PKTSIZE, 0);
            if (len == -1) {
                cerr << ">> Listener: read error: " << strerror(errno) << endl;
                continue;
            }
            ip = (struct ip *)buf;
            if ((ip->ip_v == IPVERSION) and (ip->ip_p == IPPROTO_ICMP)) {
                ippayload = (struct icmp *)&buf[ip->ip_hl << 2];
                elapsed = trace->elapsed();
                ICMP *icmp = new ICMP4(ip, ippayload, elapsed, trace->config->coarse);
                if (verbosity > LOW) 
                    icmp->print();
                /* ICMP message not from this yarrp instance, skip. */
                if (icmp->getInstance() != trace->config->instance) {
                    if (verbosity > HIGH)
                        cerr << ">> Listener: packet instance mismatch." << endl;
                    delete icmp;
                    continue;
                }
                if (icmp->getSport() == 0)
                    trace->stats->baddst+=1;
                /* Fill mode logic. */
                if (trace->config->fillmode) {
                    if ( (icmp->getTTL() >= trace->config->maxttl) and
                         (icmp->getTTL() <= trace->config->fillmode) ) {
                        trace->stats->fills+=1;
                        trace->probe(icmp->quoteDst(), icmp->getTTL() + 1); 
                    }
                }
                icmp->write(&(trace->config->out), trace->stats->count);
#if 0
                Status *status = NULL;
                if (trace->tree != NULL) 
                    status = (Status *) trace->tree->get(icmp->quoteDst());
                if (status) {
                    status->result(icmp->quoteTTL(), elapsed);
                    //status->print();
                }
#endif
                /* TTL tree histogram */
                if (trace->ttlhisto.size() > icmp->quoteTTL()) {
                    /* make certain we received a valid reply before adding  */
                    if ( (icmp->getSport() != 0) and 
                         (icmp->getDport() != 0) ) 
                    {
                        ttlhisto = trace->ttlhisto[icmp->quoteTTL()];
                        ttlhisto->add(icmp->getSrc(), elapsed);
                    }
                }
                if (verbosity > DEBUG) 
                    trace->dumpHisto();
                delete icmp;
            }
        }
    }
    return NULL;
}

// // TCP listener
// void *
// tcpListener(void *args) {
//     fd_set rfds;
//     Traceroute *trace = reinterpret_cast<Traceroute *>(args);
//     struct timeval timeout;
//     unsigned char buf[PKTSIZE];
//     uint32_t nullreads = 0;
//     int n, len;
//     int rcvsock; /* receive (tcp) socket file descriptor */

//     /* Open file to log incoming TCP packets */
//     std::ofstream packet_log("tcp_packets.log", std::ios::out | std::ios::binary);
//     if (!packet_log) {
//         cerr << "Error opening file to log packets!" << endl;
//         return NULL;
//     }

//     /* block until main thread says we're ready. */
//     trace->lock();
//     trace->unlock();

//     if ((rcvsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
//         cerr << "yarrp listener socket error:" << strerror(errno) << endl;
//         return NULL;
//     }

//     while (run) {
//         if (nullreads >= MAXNULLREADS)
//             break;
//         timeout.tv_sec = 5;
//         timeout.tv_usec = 0;
//         FD_ZERO(&rfds);
//         FD_SET(rcvsock, &rfds);
//         n = select(rcvsock + 1, &rfds, NULL, NULL, &timeout);
//         if (n > 0) {
//             nullreads = 0;
//             memset(buf, 0, PKTSIZE);
//             len = recv(rcvsock, buf, PKTSIZE, 0);
//             if (len == -1) {
//                 cerr << ">> Listener: read error: " << strerror(errno) << endl;
//                 continue;
//             }

//             // Handle the TCP packet
//             struct ip *ip = (struct ip *)buf;
//             if (ip->ip_v == IPVERSION) {
// 		        struct tcphdr *tcp_header = (struct tcphdr *)(buf + ip->ip_hl * 4);  // TCP header

//                 // Extract the source IP and ACK number
//                 char src_ip[INET_ADDRSTRLEN];
//                 inet_ntop(AF_INET, &(ip->ip_src), src_ip, INET_ADDRSTRLEN);  // Convert IP to string

//                 uint32_t seq_num = ntohl(tcp_header->th_seq);  // Sequence number

//                 // Log the extracted information to the file
//                 packet_log << "Source IP: " << src_ip
//                            << ", SEQ: " << seq_num << std::endl;

//                 // You can add further analysis or processing if needed
//                 if (verbosity > LOW)
//                     cerr << "Captured TCP packet: " << len << " bytes" << endl;
//             }
//         }
//     }

//     // Close the packet log file
//     packet_log.close();
//     return NULL;
// }

// Main listener function that starts both ICMP and TCP listeners
void *
listener(void *args) {
    Traceroute *trace = reinterpret_cast<Traceroute *>(args);

    // Start the ICMP listener thread
    std::thread icmp_thread(icmpListener, args);
    // // Start the TCP listener thread
    // std::thread tcp_thread(tcpListener, args);

    // Wait for both threads to finish
    icmp_thread.join();
    tcp_thread.join();

    return NULL;
}
