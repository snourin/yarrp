/****************************************************************************
   Program:     $Id: trace.cpp 39 2015-12-30 20:28:36Z rbeverly $
   Date:        $Date: 2015-12-30 12:28:36 -0800 (Wed, 30 Dec 2015) $
   Description: traceroute class
****************************************************************************/
#include "yarrp.h"

#ifndef HOST
#define HOST "example.com"
#endif

#define PAYLOAD "GET / HTTP/1.1\r\nHost: " HOST "\r\n\r\n"
#define PAYLOAD_LEN strlen(PAYLOAD) 

static unsigned int tlsPayloadLength;
static unsigned char *tlsPayload;
static unsigned int totalPayloadLength;

static void initialize_https_payload(){
    // Current UNIX timestamp
    time_t current_time = time(NULL);
    uint32_t timestamp = htonl((uint32_t)current_time); // Convert to network byte order

	unsigned char tlsHeader[] = {0x16, 0x03, 0x01};
	unsigned char tlsLength[2];
	unsigned char clientHello[] = {0x01};
	unsigned char clientHelloLength[3];
    unsigned char everythingBeforeSNI[] = {
        0x03, 0x03, 0xc4, 0x33, 0xd7, 0xd9, 0x7a, 0x9d, 0xdc, 0x2b, 0x6c, 0xc0, 0x2b, 0x40, 0x3d, 0x31, 
        0xf3, 0x29, 0x89, 0x6f, 0x6a, 0x5f, 0x52, 0x89, 0x2b, 0xb6, 0x2b, 0x1f, 0x6c, 0xa7, 0x08, 0xe1, 
        0x33, 0x9e, 0x20, 0x0f, 0xa9, 0x83, 0xda, 0x1f, 0xb7, 0xfe, 0xb5, 0xf8, 0xb4, 0x66, 0x58, 0x2b, 
        0xa1, 0xf3, 0xe0, 0xe4, 0x7a, 0x2d, 0xae, 0xd4, 0xe4, 0x21, 0x21, 0xa3, 0x82, 0xbc, 0xa1, 0xcc, 
        0x70, 0x82, 0x2f, 0x00, 0x3e, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0xc0, 0x2c, 0xc0, 0x30, 0x00, 
        0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 
        0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 
        0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 
        0x2f, 0x00, 0xff, 0x01, 0x00, 0x00, 0x00
    };

    unsigned int exampleDotComExtensionLength = 169;
    unsigned int lengthDiffWithExampleDotCom = strlen(HOST) - strlen("example.com");
    unsigned int extensionLength = exampleDotComExtensionLength + lengthDiffWithExampleDotCom;
    everythingBeforeSNI[133] = (extensionLength >> 8) & 0xFF;
    everythingBeforeSNI[134] = (extensionLength) & 0xFF;

	unsigned char extensionType[] = {0x00, 0x00};
	unsigned char serverNameExtensionLength[2];
	unsigned char serverNameListLength[2];
	unsigned char serverNameType[] = {0x00};
	unsigned char serverNameLength[2];
	unsigned char *serverName = (unsigned char *) HOST;
	unsigned char everythingAfterSNI[] = {
        0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x14, 0x00, 0x1d,
        0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03,
        0x01, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0d,
        0x00, 0x2a, 0x00, 0x28, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09,
        0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01,
        0x03, 0x03, 0x03, 0x01, 0x03, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x00, 0x2b, 0x00, 0x05,
        0x04, 0x03, 0x04, 0x03, 0x03, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00,
        0x24, 0x00, 0x1d, 0x00, 0x20, 0xcc, 0xea, 0x26, 0x12, 0x3f, 0xb4, 0x3d, 0xd9, 0x20, 0xdc, 0x63,
        0x9d, 0x97, 0x1e, 0xc3, 0xa6, 0x5a, 0xcd, 0x84, 0xbb, 0x5b, 0x67, 0x67, 0xda, 0xe3, 0x77, 0x13,
        0xc9, 0xc9, 0x44, 0x92, 0x00
	};
	unsigned int hostNameLength = strlen(HOST);
    unsigned int payloadLength = 292 + hostNameLength + 5;
    unsigned int clientHelloLengthValue = 288 + hostNameLength + 5;
	tlsLength[0] = (payloadLength >> 8) & 0xFF;
    tlsLength[1] = payloadLength & 0xFF;
    clientHelloLength[0] = (clientHelloLengthValue >> 16) & 0xFF;
    clientHelloLength[1] = (clientHelloLengthValue >> 8) & 0xFF;
    clientHelloLength[2] = clientHelloLengthValue & 0xFF;
    
    serverNameExtensionLength[0] = (hostNameLength + 5) >> 8 & 0xFF;
    serverNameExtensionLength[1] = (hostNameLength + 5) & 0xFF;
    serverNameListLength[0] = (hostNameLength + 3) >> 8 & 0xFF;
    serverNameListLength[1] = (hostNameLength + 3) & 0xFF;
    serverNameLength[0] = hostNameLength >> 8 & 0xFF;
    serverNameLength[1] = hostNameLength & 0xFF;

	unsigned char* sni = (unsigned char *) malloc(9 + hostNameLength);
    memcpy(sni, extensionType, 2);
    memcpy(sni + 2, serverNameExtensionLength, 2);
    memcpy(sni + 4, serverNameListLength, 2);
    memcpy(sni + 6, serverNameType, 1);
    memcpy(sni + 7, serverNameLength, 2);
    memcpy(sni + 9, serverName, hostNameLength);
    
    int sniLength = 9 + hostNameLength;
    tlsPayloadLength = sizeof(tlsHeader) + sizeof(tlsLength) + sizeof(clientHello) +
        sizeof(clientHelloLength) + sizeof(everythingBeforeSNI) + sniLength + sizeof(everythingAfterSNI);

	tlsPayload = (unsigned char *) malloc(tlsPayloadLength);
    memcpy(tlsPayload, tlsHeader, sizeof(tlsHeader));
    memcpy(tlsPayload + sizeof(tlsHeader), tlsLength, sizeof(tlsLength));
    memcpy(tlsPayload + sizeof(tlsHeader) + sizeof(tlsLength), clientHello, sizeof(clientHello));
    memcpy(tlsPayload + sizeof(tlsHeader) + sizeof(tlsLength) + sizeof(clientHello),
           clientHelloLength, sizeof(clientHelloLength));
    memcpy(tlsPayload + sizeof(tlsHeader) + sizeof(tlsLength) + sizeof(clientHello) +
           sizeof(clientHelloLength), everythingBeforeSNI, sizeof(everythingBeforeSNI));
    memcpy(tlsPayload + sizeof(tlsHeader) + sizeof(tlsLength) + sizeof(clientHello) +
           sizeof(clientHelloLength) + sizeof(everythingBeforeSNI), sni, sniLength);
    memcpy(tlsPayload + sizeof(tlsHeader) + sizeof(tlsLength) + sizeof(clientHello) +
           sizeof(clientHelloLength) + sizeof(everythingBeforeSNI) + sniLength,
           everythingAfterSNI, sizeof(everythingAfterSNI));

    //this is wrong, it says ipv6, check this

	totalPayloadLength = sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + tlsPayloadLength;

	// free(sni);
    // free(tls_payload);
}

Traceroute4::Traceroute4(YarrpConfig *_config, Stats *_stats) : Traceroute(_config, _stats)
{
    if (config->testing) return;
    memset(&source, 0, sizeof(struct sockaddr_in)); 
    if (config->probesrc) {
        source.sin_family = AF_INET;
        if (inet_pton(AF_INET, config->probesrc, &source.sin_addr) != 1)
          fatal("** Bad source address.");
        cout << ">> Using IP source: " << config->probesrc << endl;
    } else {
        infer_my_ip(&source);
    }
    inet_ntop(AF_INET, &source.sin_addr, addrstr, INET_ADDRSTRLEN);
    config->set("SourceIP", addrstr, true);
    payloadlen = 0;
    outip = (struct ip *)calloc(1, PKTSIZE);
    outip->ip_v = IPVERSION;
    outip->ip_hl = sizeof(struct ip) >> 2;
    outip->ip_src.s_addr = source.sin_addr.s_addr;
    sndsock = raw_sock(&source);
    if (config->probe and config->receive) {
        lock();   /* grab mutex; make listener thread block. */
        pthread_create(&recv_thread, NULL, listener, this);
    }
}

Traceroute4::~Traceroute4() {
    if (outip)
        free(outip);
}

void Traceroute4::probePrint(struct in_addr *targ, int ttl) {
    uint32_t diff = elapsed();
    if (config->probesrc)
        cout << inet_ntoa(source.sin_addr) << " -> ";
    cout << inet_ntoa(*targ) << " ttl: ";
    cout << ttl;
    if (config->instance)
        cout << " i=" << (int) config->instance;
    cout << " t=" << diff;
    (config->coarse) ? cout << "ms" << endl : cout << "us" << endl;
}

void
Traceroute4::probe(const char *targ, int ttl) {
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
#ifdef _BSD
    target.sin_len = sizeof(target);
#endif
    inet_aton(targ, &(target.sin_addr));
    probe(&target, ttl);
}

void
Traceroute4::probe(uint32_t addr, int ttl) {
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
#ifdef _BSD
    target.sin_len = sizeof(target);
#endif
    target.sin_addr.s_addr = addr;
    probe(&target, ttl);
}

void
Traceroute4::probe(struct sockaddr_in *target, int ttl) {
    outip->ip_ttl = ttl;
    outip->ip_id = htons(ttl + (config->instance << 8));
    outip->ip_off = 0; // htons(IP_DF);
    outip->ip_dst.s_addr = (target->sin_addr).s_addr;
    outip->ip_sum = 0;
    if (TR_UDP == config->type) {
        probeUDP(target, ttl);
    } else if ( (TR_ICMP == config->type) || (TR_ICMP_REPLY == config->type) ) {
        probeICMP(target, ttl);
    } else if ( (TR_TCP_SYN == config->type) || (TR_TCP_ACK == config->type) ) {
        probeTCP(target, ttl);
    } else if (TR_TCP_SYN_PSHACK == config->type) {
        probeTCPSYNPSHACK(target, ttl);
    } else {
        cerr << "** bad trace type:" << config->type << endl;
        assert(false);
    }
}

void
Traceroute4::probeUDP(struct sockaddr_in *target, int ttl) {
    unsigned char *ptr = (unsigned char *)outip;
    struct udphdr *udp = (struct udphdr *)(ptr + (outip->ip_hl << 2));
    unsigned char *data = (unsigned char *)(ptr + (outip->ip_hl << 2) + sizeof(struct udphdr));

    uint32_t diff = elapsed();
    payloadlen = 2;
    /* encode MSB of timestamp in UDP payload length */ 
    if (diff >> 16)
        payloadlen += (diff>>16);
    if (verbosity > HIGH) {
        cout << ">> UDP probe: ";
        probePrint(&target->sin_addr, ttl);
    }

    packlen = sizeof(struct ip) + sizeof(struct udphdr) + payloadlen;

    outip->ip_p = IPPROTO_UDP;
#if defined(_BSD) && !defined(_NEW_FBSD)
    outip->ip_len = packlen;
    outip->ip_off = IP_DF;
#else
    outip->ip_len = htons(packlen);
    outip->ip_off = ntohs(IP_DF);
#endif
    /* encode destination IPv4 address as cksum(ipdst) */
    uint16_t dport = in_cksum((unsigned short *)&(outip->ip_dst), 4);
    udp->uh_sport = htons(dport);
    udp->uh_dport = htons(dstport);
    udp->uh_ulen = htons(sizeof(struct udphdr) + payloadlen);
    udp->uh_sum = 0;

    outip->ip_sum = htons(in_cksum((unsigned short *)outip, 20));

    /* compute UDP checksum */
    memset(data, 0, 2);
    u_short len = sizeof(struct udphdr) + payloadlen;
    udp->uh_sum = p_cksum(outip, (u_short *) udp, len);

    /* encode LSB of timestamp in checksum */
    uint16_t crafted_cksum = diff & 0xFFFF;
    /* craft payload such that the new cksum is correct */
    uint16_t crafted_data = compute_data(udp->uh_sum, crafted_cksum);
    memcpy(data, &crafted_data, 2);
    if (crafted_cksum == 0x0000)
        crafted_cksum = 0xFFFF;
    udp->uh_sum = crafted_cksum;

    if (sendto(sndsock, (char *)outip, packlen, 0, (struct sockaddr *)target, sizeof(*target)) < 0) {
        cout << __func__ << "(): error: " << strerror(errno) << endl;
        cout << ">> UDP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
        cout << ttl << " t=" << diff << endl;
    }
}

void
Traceroute4::probeTCP(struct sockaddr_in *target, int ttl) {
    unsigned char *ptr = (unsigned char *)outip;
    struct tcphdr *tcp = (struct tcphdr *)(ptr + (outip->ip_hl << 2));

    packlen = sizeof(struct ip) + sizeof(struct tcphdr) + payloadlen;
    outip->ip_p = IPPROTO_TCP;
#if defined(_BSD) && !defined(_NEW_FBSD)
    outip->ip_len = packlen;
    outip->ip_off = 0; //IP_DF;
#else
    outip->ip_len = htons(packlen);
#endif
    /* encode destination IPv4 address as cksum(ipdst) */
    uint16_t dport = in_cksum((unsigned short *)&(outip->ip_dst), 4);
    tcp->th_sport = htons(dport);
    tcp->th_dport = htons(dstport);
    /* encode send time into seq no as elapsed milliseconds */
    uint32_t diff = elapsed();
    if (verbosity > HIGH) {
        cout << ">> TCP probe: ";
        probePrint(&target->sin_addr, ttl);
    }
    tcp->th_seq = htonl(diff);
    tcp->th_off = 5;
    tcp->th_win = htons(0xFFFE);
    tcp->th_sum = 0;
    /* don't want to set SYN, lest we be tagged as SYN flood. */
    if (TR_TCP_SYN == config->type) {
        tcp->th_flags |= TH_SYN;
    } else {
        tcp->th_flags |= TH_ACK;
        tcp->th_ack = htonl(target->sin_addr.s_addr);
    }
    /*
     * explicitly computing cksum probably not required on most machines
     * these days as offloaded by OS or NIC.  but we'll be safe.
     */
    outip->ip_sum = htons(in_cksum((unsigned short *)outip, 20));
    /*
     * bsd rawsock requires host ordered len and offset; rewrite here as
     * chksum must be over htons() versions
     */
    u_short len = sizeof(struct tcphdr) + payloadlen;
    tcp->th_sum = p_cksum(outip, (u_short *) tcp, len);
    if (sendto(sndsock, (char *)outip, packlen, 0, (struct sockaddr *)target, sizeof(*target)) < 0) {
        cout << __func__ << "(): error: " << strerror(errno) << endl;
        cout << ">> TCP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
        cout << ttl << " t=" << diff << endl;
    }
}

void set_ack_msb_to_ttl(struct tcphdr *tcp_hdr, uint8_t ttl) {
    uint32_t ack_num = ntohl(tcp_hdr->th_ack);

    // Set MSB to TTL while preserving the lower 24 bits
    //ack_num = (ttl << 24) | (ack_num & 0x00FFFFFF);
    ack_num = ttl;

    tcp_hdr->th_ack = htonl(ack_num);

    cout << tcp_hdr->th_ack << endl;
}


// HTTP
void
Traceroute4::probeTCPSYNPSHACK(struct sockaddr_in *target, int ttl) {
    std::string domain;
    auto it = domain_map.find(target->sin_addr.s_addr);
    if (it != domain_map.end()) {
        domain = it->second;
    } else {
        domain = "example.com";  // fallback if no domain known
    }

    // SYN
    unsigned char *ptr_syn = (unsigned char *)outip;
    struct tcphdr *tcp_syn = (struct tcphdr *)(ptr_syn + (outip->ip_hl << 2));

    packlen = sizeof(struct ip) + sizeof(struct tcphdr) + payloadlen;
    outip->ip_p = IPPROTO_TCP;
#if defined(_BSD) && !defined(_NEW_FBSD)
    outip->ip_len = packlen;
    outip->ip_off = 0; //IP_DF;
#else
    outip->ip_len = htons(packlen);
#endif
    /* encode destination IPv4 address as cksum(ipdst) */
    uint16_t dport = in_cksum((unsigned short *)&(outip->ip_dst), 4);
    tcp_syn->th_sport = htons(dport);
    tcp_syn->th_dport = htons(dstport);
    /* encode send time into seq no as elapsed milliseconds */
    uint32_t diff = elapsed();
    if (verbosity > HIGH) {
        cout << ">> TCP probe: ";
        probePrint(&target->sin_addr, ttl);
    }

    tcp_syn->th_seq = htonl(diff);
    tcp_syn->th_off = 5;
    tcp_syn->th_win = htons(0xFFFE);
    tcp_syn->th_sum = 0;

    /* encode TTL within TCP ack number */
    set_ack_msb_to_ttl(tcp_syn, uint8_t(ttl));

    tcp_syn->th_flags = TH_SYN;

    /*
     * explicitly computing cksum probably not required on most machines
     * these days as offloaded by OS or NIC.  but we'll be safe.
     */
    outip->ip_sum = htons(in_cksum((unsigned short *)outip, 20));
    /*
     * bsd rawsock requires host ordered len and offset; rewrite here as
     * chksum must be over htons() versions
     */
    u_short len_syn = sizeof(struct tcphdr) + payloadlen;
    tcp_syn->th_sum = p_cksum(outip, (u_short *) tcp_syn, len_syn);
    if (sendto(sndsock, (char *)outip, packlen, 0, (struct sockaddr *)target, sizeof(*target)) < 0) {
        cout << __func__ << "(): error: " << strerror(errno) << endl;
        cout << ">> TCP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
        cout << ttl << " t=" << diff << endl;
    }

    // PSH+ACK
    unsigned char *ptr = (unsigned char *)outip;
    struct tcphdr *tcp = (struct tcphdr *)(ptr + (outip->ip_hl << 2));
    unsigned char *payload = (unsigned char *)tcp + (tcp->th_off << 2);

    std::string payload_str = "GET / HTTP/1.1\r\nHost: " + domain + "\r\n\r\n";

    packlen = sizeof(struct ip) + sizeof(struct tcphdr) + payload_str.length();
    outip->ip_p = IPPROTO_TCP;
#if defined(_BSD) && !defined(_NEW_FBSD)
    outip->ip_len = packlen;
    outip->ip_off = 0; //IP_DF;
#else
    outip->ip_len = htons(packlen);
#endif
    /* Set HTTP GET request as TCP payload */
    memcpy(payload, payload_str.c_str(), payload_str.length());

    /* encode destination IPv4 address as cksum(ipdst) */
    //uint16_t dport = in_cksum((unsigned short *)&(outip->ip_dst), 4);
    tcp->th_sport = htons(dport);
    tcp->th_dport = htons(dstport);
    /* encode send time into seq no as elapsed milliseconds */
    // uint32_t diff = elapsed();
    // if (verbosity > HIGH) {
    //     cout << ">> TCP probe: ";
    //     probePrint(&target->sin_addr, ttl);
    // }
    /* encode TTL within TCP sequence number */
    tcp->th_seq = htonl(diff + 1);
    tcp->th_off = 5;
    tcp->th_win = htons(0xFFFE);
    tcp->th_sum = tcp_checksum(sizeof(struct tcphdr), outip->ip_src.s_addr, outip->ip_dst.s_addr, tcp);

    /* encode TTL within TCP sequence number */
    set_ack_msb_to_ttl(tcp, uint8_t(ttl));

    /* Set TCP flag to be PSH+ACK */
    tcp->th_flags = TH_PUSH | TH_ACK;
    //tcp->th_ack = htonl(target->sin_addr.s_addr);

    /*
     * explicitly computing cksum probably not required on most machines
     * these days as offloaded by OS or NIC.  but we'll be safe.
     */
    outip->ip_sum = htons(in_cksum((unsigned short *)outip, 20));
    /*
     * bsd rawsock requires host ordered len and offset; rewrite here as
     * chksum must be over htons() versions
     */
    u_short len = sizeof(struct tcphdr) + payload_str.length();
    tcp->th_sum = p_cksum(outip, (u_short *) tcp, payload_str.length());
    if (sendto(sndsock, (char *)outip, packlen, 0, (struct sockaddr *)target, sizeof(*target)) < 0) {
        cout << __func__ << "(): error: " << strerror(errno) << endl;
        cout << ">> TCP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
        cout << ttl << " t=" << diff << endl;
    }
}

// //HTTPS
// void
// Traceroute4::probeTCPSYNPSHACK(struct sockaddr_in *target, int ttl) {
//     initialize_https_payload();


//     // SYN
//     unsigned char *ptr_syn = (unsigned char *)outip;
//     struct tcphdr *tcp_syn = (struct tcphdr *)(ptr_syn + (outip->ip_hl << 2));

//     packlen = sizeof(struct ip) + sizeof(struct tcphdr) + payloadlen;
//     outip->ip_p = IPPROTO_TCP;
// #if defined(_BSD) && !defined(_NEW_FBSD)
//     outip->ip_len = packlen;
//     outip->ip_off = 0; //IP_DF;
// #else
//     outip->ip_len = htons(packlen);
// #endif
//     /* encode destination IPv4 address as cksum(ipdst) */
//     uint16_t dport = in_cksum((unsigned short *)&(outip->ip_dst), 4);
//     tcp_syn->th_sport = htons(dport);
//     tcp_syn->th_dport = htons(dstport);
//     /* encode send time into seq no as elapsed milliseconds */
//     uint32_t diff = elapsed();
//     if (verbosity > HIGH) {
//         cout << ">> TCP probe: ";
//         probePrint(&target->sin_addr, ttl);
//     }
//     tcp_syn->th_seq = htonl(diff);
//     tcp_syn->th_off = 5;
//     tcp_syn->th_win = htons(0xFFFE);
//     tcp_syn->th_sum = 0;

//     tcp_syn->th_flags = TH_SYN;

//     /*
//      * explicitly computing cksum probably not required on most machines
//      * these days as offloaded by OS or NIC.  but we'll be safe.
//      */
//     outip->ip_sum = htons(in_cksum((unsigned short *)outip, 20));
//     /*
//      * bsd rawsock requires host ordered len and offset; rewrite here as
//      * chksum must be over htons() versions
//      */
//     u_short len_syn = sizeof(struct tcphdr) + payloadlen;
//     tcp_syn->th_sum = p_cksum(outip, (u_short *) tcp_syn, len_syn);
//     if (sendto(sndsock, (char *)outip, packlen, 0, (struct sockaddr *)target, sizeof(*target)) < 0) {
//         cout << __func__ << "(): error: " << strerror(errno) << endl;
//         cout << ">> TCP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
//         cout << ttl << " t=" << diff << endl;
//     }

//     // PSH+ACK
//     unsigned char *ptr = (unsigned char *)outip;
//     struct tcphdr *tcp = (struct tcphdr *)(ptr + (outip->ip_hl << 2));
//     unsigned char *payload = (unsigned char *)tcp + (tcp->th_off << 2);

//     packlen = sizeof(struct ip) + sizeof(struct tcphdr) + tlsPayloadLength;
//     outip->ip_p = IPPROTO_TCP;
// #if defined(_BSD) && !defined(_NEW_FBSD)
//     outip->ip_len = packlen;
//     outip->ip_off = 0; //IP_DF;
// #else
//     outip->ip_len = htons(packlen);
// #endif
//     /* Set HTTP GET request as TCP payload */
//     memcpy(payload, tlsPayload, tlsPayloadLength);

//     /* encode destination IPv4 address as cksum(ipdst) */
//     //uint16_t dport = in_cksum((unsigned short *)&(outip->ip_dst), 4);
//     tcp->th_sport = htons(dport);
//     tcp->th_dport = htons(dstport);
//     /* encode send time into seq no as elapsed milliseconds */
//     // uint32_t diff = elapsed();
//     // if (verbosity > HIGH) {
//     //     cout << ">> TCP probe: ";
//     //     probePrint(&target->sin_addr, ttl);
//     // }
//     tcp->th_seq = htonl(diff + 1);
//     tcp->th_off = 5;
//     tcp->th_win = htons(0xFFFE);
//     tcp->th_sum = tcp_checksum(sizeof(struct tcphdr), outip->ip_src.s_addr, outip->ip_dst.s_addr, tcp);

//     /* Set TCP flag to be PSH+ACK */
//     tcp->th_flags = TH_PUSH | TH_ACK;
//     tcp->th_ack = htonl(target->sin_addr.s_addr);

//     /*
//      * explicitly computing cksum probably not required on most machines
//      * these days as offloaded by OS or NIC.  but we'll be safe.
//      */
//     outip->ip_sum = htons(in_cksum((unsigned short *)outip, 20));
//     /*
//      * bsd rawsock requires host ordered len and offset; rewrite here as
//      * chksum must be over htons() versions
//      */
//     u_short len = sizeof(struct tcphdr) + tlsPayloadLength;
//     tcp->th_sum = p_cksum(outip, (u_short *) tcp, len);
//     if (sendto(sndsock, (char *)outip, packlen, 0, (struct sockaddr *)target, sizeof(*target)) < 0) {
//         cout << __func__ << "(): error: " << strerror(errno) << endl;
//         cout << ">> TCP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
//         cout << ttl << " t=" << diff << endl;
//     }
// }

void
Traceroute4::probeICMP(struct sockaddr_in *target, int ttl) {
    unsigned char *ptr = (unsigned char *)outip;
    struct icmp *icmp = (struct icmp *)(ptr + (outip->ip_hl << 2));
    unsigned char *data = (unsigned char *)(ptr + (outip->ip_hl << 2) + ICMP_MINLEN);

    payloadlen = 2;
    packlen = sizeof(struct ip) + ICMP_MINLEN + payloadlen;
    outip->ip_p = IPPROTO_ICMP;
    outip->ip_len = htons(packlen);
#if defined(_BSD) && !defined(_NEW_FBSD)
    outip->ip_len = packlen;
    outip->ip_off = 0; //IP_DF;
#else
    outip->ip_len = htons(packlen);
#endif
    /* encode send time into icmp id and seq as elapsed milli/micro seconds */
    uint32_t diff = elapsed();
    if (verbosity > HIGH) {
        cout << ">> ICMP probe: ";
        probePrint(&target->sin_addr, ttl);
    }
    icmp->icmp_type = ICMP_ECHO;
    if (TR_ICMP_REPLY == config->type)
        icmp->icmp_type = ICMP_ECHOREPLY;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_id = htons(diff & 0xFFFF);
    icmp->icmp_seq = htons((diff >> 16) & 0xFFFF);
    outip->ip_sum = htons(in_cksum((unsigned short *)outip, 20));

    /* compute ICMP checksum */
    memset(data, 0, 2);
    u_short len = ICMP_MINLEN + payloadlen;
    icmp->icmp_cksum = in_cksum((u_short *) icmp, len);

    /* encode cksum(ipdst) into checksum */
    uint16_t crafted_cksum = in_cksum((unsigned short *)&(outip->ip_dst), 4);
    /* craft payload such that the new cksum is correct */
    uint16_t crafted_data = compute_data(icmp->icmp_cksum, crafted_cksum);
    memcpy(data, &crafted_data, 2);
    if (crafted_cksum == 0x0000)
        crafted_cksum = 0xFFFF;
    icmp->icmp_cksum = crafted_cksum;

    if (sendto(sndsock, (char *)outip, packlen, 0, (struct sockaddr *)target, sizeof(*target)) < 0) {
        cout << __func__ << "(): error: " << strerror(errno) << endl;
        cout << ">> ICMP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
        cout << ttl << " t=" << diff << endl;
    }
}
