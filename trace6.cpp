/****************************************************************************
   Program:     $Id: trace.cpp 39 2015-12-30 20:28:36Z rbeverly $
   Date:        $Date: 2015-12-30 12:28:36 -0800 (Wed, 30 Dec 2015) $
   Description: traceroute class
****************************************************************************/
#include "yarrp.h"

static unsigned int tlsPayloadLength;
static unsigned char *tlsPayload;
static unsigned int totalPayloadLength;

static void initialize_https_payload(const char* domain){
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
    unsigned int lengthDiffWithExampleDotCom = strlen(domain) - strlen("example.com");
    unsigned int extensionLength = exampleDotComExtensionLength + lengthDiffWithExampleDotCom;
    everythingBeforeSNI[133] = (extensionLength >> 8) & 0xFF;
    everythingBeforeSNI[134] = (extensionLength) & 0xFF;

	unsigned char extensionType[] = {0x00, 0x00};
	unsigned char serverNameExtensionLength[2];
	unsigned char serverNameListLength[2];
	unsigned char serverNameType[] = {0x00};
	unsigned char serverNameLength[2];
	unsigned char *serverName = (unsigned char *) domain;
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
	unsigned int hostNameLength = strlen(domain);
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

Traceroute6::Traceroute6(YarrpConfig *_config, Stats *_stats) : Traceroute(_config, _stats) {
    if (config->testing) return;
    memset(&source6, 0, sizeof(struct sockaddr_in6));
    if (config->probesrc) {
        source6.sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, config->probesrc, &source6.sin6_addr) != 1)
          fatal("** Bad source address."); 
    } else {
        infer_my_ip6(&source6);
    }
    inet_ntop(AF_INET6, &source6.sin6_addr, addrstr, INET6_ADDRSTRLEN);
    config->set("SourceIP", addrstr, true);
#ifdef _LINUX
    sndsock = raw_sock6(&source6);
#else
    /* Init BPF socket */
    sndsock = bpfget();
    if (sndsock < 0) fatal("bpf open error\n");
    struct ifreq bound_if;
    strcpy(bound_if.ifr_name, config->int_name);
    if (ioctl(sndsock, BIOCSETIF, &bound_if) > 0) fatal("ioctl err\n");
#endif
    pcount = 0;

    assert(config);
    assert(config->srcmac);

    /* Set Ethernet header */
    frame = (uint8_t *)calloc(1, PKTSIZE);
    memcpy (frame, config->dstmac, 6 * sizeof (uint8_t));
    memcpy (frame + 6, config->srcmac, 6 * sizeof (uint8_t));
    frame[12] = 0x86; /* IPv6 Ethertype */
    frame[13] = 0xdd;

    /* Set static IP6 header fields */
    outip = (struct ip6_hdr *) (frame + ETH_HDRLEN);
    outip->ip6_flow = htonl(0x6<<28|tc<<20|flow);
    outip->ip6_src = source6.sin6_addr;

    /* Init yarrp payload struct */
    payload = (struct ypayload *)malloc(sizeof(struct ypayload));
    payload->id = htonl(0x79727036);
    payload->instance = config->instance;

    if (config->probe and config->receive) {
        pthread_create(&recv_thread, NULL, listener6, this);
        /* give listener thread time to startup */
        sleep(1);
    }
}

Traceroute6::~Traceroute6() {
    if (config->testing) return;
    free(frame);
}

void Traceroute6::probePrint(struct in6_addr addr, int ttl) {
    uint32_t diff = elapsed();
    if (config->probesrc) {
        inet_ntop(AF_INET6, &source6.sin6_addr, addrstr, INET6_ADDRSTRLEN);
        cout << addrstr << " -> ";
    }
    inet_ntop(AF_INET6, &addr, addrstr, INET6_ADDRSTRLEN);
    cout << addrstr << " ttl: " << ttl << " t=" << diff;
    (config->coarse) ? cout << "ms" << endl : cout << "us" << endl;
}

void
Traceroute6::probe(struct in6_addr addr, int ttl) {
#ifdef _LINUX 
    struct sockaddr_ll target;
    memset(&target, 0, sizeof(target));
    target.sll_ifindex = if_nametoindex(config->int_name);
    target.sll_family = AF_PACKET;
    memcpy(target.sll_addr, config->srcmac, 6 * sizeof(uint8_t));
    target.sll_halen = 6;
    probe(&target, addr, ttl);
#else
    probe(NULL, addr, ttl);
#endif
}

void
Traceroute6::probe(void *target, struct in6_addr addr, int ttl) {
    outip->ip6_hlim = ttl;
    outip->ip6_dst = addr;

    uint16_t ext_hdr_len = 0;
    uint16_t transport_hdr_len = 0;
    switch(config->type) {
      case TR_ICMP6:
        outip->ip6_nxt = IPPROTO_ICMPV6;
        transport_hdr_len = sizeof(struct icmp6_hdr);
        break;
      case TR_UDP6:
        outip->ip6_nxt = IPPROTO_UDP;
        transport_hdr_len = sizeof(struct udphdr);
        break;
      case TR_TCP6_SYN:
      case TR_TCP6_ACK:
      case TR_TCP6_SYN_PSHACK:
        outip->ip6_nxt = IPPROTO_TCP;
        transport_hdr_len = sizeof(struct tcphdr);
        break;
      default:
        cerr << "** bad trace type" << endl;
        assert(false);
    } 

    /* Shim in an extension header? */
    if (config->v6_eh != 255) {
        if (config->v6_eh == 44) {
            make_frag_eh(outip->ip6_nxt);
        } else {
            make_hbh_eh(outip->ip6_nxt);
        }
        outip->ip6_nxt = config->v6_eh; 
        ext_hdr_len = 8;
    }

    u_char *data;
    if (config->type != TR_TCP6_SYN_PSHACK) {
        /* Populate a yarrp payload */
        payload->ttl = ttl;
        payload->fudge = 0;
        payload->target = addr;
        uint32_t diff = elapsed();
        payload->diff = diff;
        data = (u_char *)(frame + ETH_HDRLEN + sizeof(ip6_hdr) 
                                + ext_hdr_len + transport_hdr_len);
        payload->instance = config->instance;
        memcpy(data, payload, sizeof(struct ypayload));
        packlen = transport_hdr_len + sizeof(struct ypayload);
    }

    /* xmit frame */
    if (verbosity > HIGH) {
      cout << ">> " << Tr_Type_String[config->type] << " probe: ";
      probePrint(addr, ttl);
    }
#ifdef _LINUX
    if (config->type == TR_TCP6_SYN_PSHACK) {
        //packlen will be set in the make_transport() function

        // send SYN
        make_transport(ext_hdr_len, ttl, addr); /* Populate transport header */
        outip->ip6_plen = htons(packlen + ext_hdr_len);
        uint16_t framelen = ETH_HDRLEN + sizeof(ip6_hdr) + ext_hdr_len + packlen;
        if (sendto(sndsock, frame, framelen, 0, (struct sockaddr *)target, sizeof(struct sockaddr_ll)) < 0)
        {
            fatal("%s: error: %s", __func__, strerror(errno));
        }
        pcount++;

        // send PSH+ACK
        make_transport(ext_hdr_len, ttl, addr, true); /* Populate transport header */
        outip->ip6_plen = htons(packlen + ext_hdr_len);
        framelen = ETH_HDRLEN + sizeof(ip6_hdr) + ext_hdr_len + packlen;
        if (sendto(sndsock, frame, framelen, 0, (struct sockaddr *)target, sizeof(struct sockaddr_ll)) < 0)
        {
            fatal("%s: error: %s", __func__, strerror(errno));
        }
        pcount++;
    } else {
        make_transport(ext_hdr_len, ttl, addr); /* Populate transport header */
        /* Copy yarrp payload again, after changing fudge for cksum */
        memcpy(data, payload, sizeof(struct ypayload));
        outip->ip6_plen = htons(packlen + ext_hdr_len);
        uint16_t framelen = ETH_HDRLEN + sizeof(ip6_hdr) + ext_hdr_len + packlen;
        if (sendto(sndsock, frame, framelen, 0, (struct sockaddr *)target, sizeof(struct sockaddr_ll)) < 0)
        {
            fatal("%s: error: %s", __func__, strerror(errno));
        }
        pcount++;
    }
#else
    /* use the BPF to send */
    if (config->type == TR_TCP6_SYN_PSHACK) {
        // send SYN
        make_transport(ext_hdr_len, ttl, addr); /* Populate transport header */
        outip->ip6_plen = htons(packlen + ext_hdr_len);
        uint16_t framelen = ETH_HDRLEN + sizeof(ip6_hdr) + ext_hdr_len + packlen;
        write(sndsock, frame, framelen);
        pcount++;

        // send PSH+ACK
        make_transport(ext_hdr_len, ttl, addr, true); /* Populate transport header */
        outip->ip6_plen = htons(packlen + ext_hdr_len);
        framelen = ETH_HDRLEN + sizeof(ip6_hdr) + ext_hdr_len + packlen;
        write(sndsock, frame, framelen);
        pcount++;

    } else {
        make_transport(ext_hdr_len, ttl, addr); /* Populate transport header */
        /* Copy yarrp payload again, after changing fudge for cksum */
        memcpy(data, payload, sizeof(struct ypayload));
        outip->ip6_plen = htons(packlen + ext_hdr_len);
        uint16_t framelen = ETH_HDRLEN + sizeof(ip6_hdr) + ext_hdr_len + packlen;
        write(sndsock, frame, framelen);
        pcount++;
    }
#endif
}

void
Traceroute6::make_frag_eh(uint8_t nxt) {
    void *transport = frame + ETH_HDRLEN + sizeof(ip6_hdr);
    struct ip6_frag *eh = (struct ip6_frag *) transport;
    eh->ip6f_nxt = nxt;  
    eh->ip6f_reserved = 0;
    eh->ip6f_offlg = 0;
    eh->ip6f_ident = 0x8008;
}

void
Traceroute6::make_hbh_eh(uint8_t nxt) {
    uint8_t *transport = frame + ETH_HDRLEN + sizeof(ip6_hdr);
    struct ip6_ext *eh = (struct ip6_ext *) transport;
    eh->ip6e_nxt = nxt;  
    eh->ip6e_len = 0;
    transport+=2;
    struct ip6_opt *opt = (struct ip6_opt *) transport;
    opt->ip6o_type = IP6OPT_PADN;
    opt->ip6o_len = 4;
    transport+=2;
    memset(transport, 0, 4);
}

uint64_t set_low_bits(uint32_t id, uint8_t instance, uint8_t ttl, uint16_t fudge) {
    uint64_t low_bits = 0;

    low_bits |= static_cast<uint64_t>(id) << 32;
    low_bits |= static_cast<uint64_t>(instance) << 24;
    low_bits |= static_cast<uint64_t>(ttl) << 16;
    low_bits |= static_cast<uint64_t>(fudge);

    return low_bits;
}

void 
Traceroute6::make_transport(int ext_hdr_len, int ttl, struct in6_addr addr, bool censorship_second_pkt) {
    std::string domain;
    int domain_index;
    char ip_str[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &addr, ip_str, sizeof(ip_str));

    auto it = domain_map_v6.find(ip_str);
    if (it != domain_map_v6.end()) {
        domain = it->second.first;
        domain_index = it->second.second;
    } else {
        domain = "example.com";  // fallback if no domain found
        domain_index = 2;
    }

    void *transport = frame + ETH_HDRLEN + sizeof(ip6_hdr) + ext_hdr_len;
    uint16_t sum = in_cksum((unsigned short *)&(outip->ip6_dst), 16);
    if (config->type == TR_ICMP6) {
        struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)transport;
        icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6->icmp6_code = 0;
        icmp6->icmp6_cksum = 0;
        icmp6->icmp6_id = htons(sum);
        icmp6->icmp6_seq = htons(pcount);
        icmp6->icmp6_cksum = p_cksum(outip, (u_short *) icmp6, packlen);
    } else if (config->type == TR_UDP6) {
        struct udphdr *udp = (struct udphdr *)transport;
        udp->uh_sport = htons(sum);
        udp->uh_dport = htons(dstport);
        udp->uh_ulen = htons(packlen);
        udp->uh_sum = 0;
        udp->uh_sum = p_cksum(outip, (u_short *) udp, packlen);
        /* set checksum for paris goodness */
        uint16_t crafted_cksum = htons(0xbeef);
        payload->fudge = compute_data(udp->uh_sum, crafted_cksum);
        udp->uh_sum = crafted_cksum;
    } else if (config->type == TR_TCP6_SYN || config->type == TR_TCP6_ACK) {
        struct tcphdr *tcp = (struct tcphdr *)transport;
        
        const uint32_t DOMAIN_INDEX_MASK = 0x1FF << 7;
        const uint32_t DST_IP_CHKSM_MASK = 0x7F;

        uint16_t pkt_sport = 0;

        pkt_sport |= (domain_index & 0x1FF) << 7;
        pkt_sport |= ((in_cksum((unsigned short *)&(outip->ip6_dst), 16) >> 9) & 0x7F);

        tcp->th_sport = htons(pkt_sport);
        tcp->th_dport = htons(dstport);
        tcp->th_seq = htonl(1);
        tcp->th_off = 5;
        tcp->th_win = htons(65535);
        tcp->th_sum = 0;
        tcp->th_x2 = 0;
        tcp->th_flags = 0;
        tcp->th_urp = htons(0);
        if (config->type == TR_TCP6_SYN) 
           tcp->th_flags |= TH_SYN; 
        else
           tcp->th_flags = TH_ACK; 
        tcp->th_sum = p_cksum(outip, (u_short *) tcp, packlen);
        /* set checksum for paris goodness */
        uint16_t crafted_cksum = htons(0xbeef);
        payload->fudge = compute_data(tcp->th_sum, crafted_cksum);
        tcp->th_sum = crafted_cksum;
    } else if (config->type == TR_TCP6_SYN_PSHACK) {
        struct tcphdr *tcp = (struct tcphdr *)transport; 

        const uint32_t DOMAIN_INDEX_MASK = 0x1FF << 7;
        const uint32_t DST_IP_CHKSM_MASK = 0x7F;

        uint16_t pkt_sport = 0;

        pkt_sport |= (domain_index & 0x1FF) << 7;
        pkt_sport |= ((in_cksum((unsigned short *)&(outip->ip6_dst), 16) >> 9) & 0x7F);

        tcp->th_sport = htons(pkt_sport);
        tcp->th_dport = htons(dstport);
        tcp->th_off = 5;
        tcp->th_win = htons(65535);
        tcp->th_sum = 0;
        tcp->th_x2 = 0;
        tcp->th_urp = htons(0);

        /* encode TTL within TCP ack number */
        set_ack_msb_to_ttl_instance_id(tcp, uint8_t(ttl), config->instance);

        if (!censorship_second_pkt) {
            uint32_t diff = elapsed();
            tcp->th_seq = htonl(diff);
            censored_syn_seq_num = diff;
            tcp->th_flags = TH_SYN;
            packlen = sizeof(struct tcphdr);
            tcp->th_sum = p_cksum(outip, (u_short *) tcp, packlen);
        } else {
            tcp->th_seq = htonl(censored_syn_seq_num + 1);
            tcp->th_flags = TH_PUSH | TH_ACK;
            packlen = sizeof(struct tcphdr); //change this
            tcp->th_sum = p_cksum(outip, (u_short *) tcp, packlen);

            unsigned char *tcp_payload = (unsigned char *)tcp + (tcp->th_off << 2);
            if (!config->use_https) {
                /* Set HTTP GET request as TCP payload */
                std::string tcp_payload_str = "GET / HTTP/1.1\r\nHost: " + domain + "\r\n\r\n";
                packlen = sizeof(struct tcphdr) + tcp_payload_str.length();
                memcpy(tcp_payload, tcp_payload_str.c_str(), tcp_payload_str.length());
            } else {
                /* Set HTTPS TLS Client Hello request as TCP payload */
                initialize_https_payload(domain.c_str());
                packlen = sizeof(struct tcphdr) + tlsPayloadLength;
                memcpy(tcp_payload, tlsPayload, tlsPayloadLength);
            }
        }

        /* set checksum for paris goodness */
        uint16_t crafted_cksum = htons(0xbeef);
        uint16_t fudge = compute_data(tcp->th_sum, crafted_cksum);
        tcp->th_sum = crafted_cksum;

        /* encode first 8 bytes of yarrp payload into lower 64 bits of the source IPv6 address */
        uint64_t high_bits = *(uint64_t*)&outip->ip6_src.s6_addr[0];
        uint32_t id = 0x79727036;
        uint64_t low_bits = set_low_bits(id, config->instance, uint8_t(ttl), fudge);
        low_bits = htobe64(low_bits);
        memcpy(outip->ip6_src.s6_addr, &high_bits, 8);
        memcpy(outip->ip6_src.s6_addr + 8, &low_bits, 8);
    }
}
