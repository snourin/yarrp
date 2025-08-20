/****************************************************************************
   Program:     $Id: trace.cpp 39 2015-12-30 20:28:36Z rbeverly $
   Date:        $Date: 2015-12-30 12:28:36 -0800 (Wed, 30 Dec 2015) $
   Description: traceroute class
****************************************************************************/
#include "yarrp.h"

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

    if (config->type != TR_TCP6_SYN_PSHACK) {
        /* Populate a yarrp payload */
        payload->ttl = ttl;
        payload->fudge = 0;
        payload->target = addr;
        uint32_t diff = elapsed();
        payload->diff = diff;
        u_char *data = (u_char *)(frame + ETH_HDRLEN + sizeof(ip6_hdr) 
                                + ext_hdr_len + transport_hdr_len);
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
        tcp->th_sport = htons(sum);
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
           tcp->th_flags |= TH_ACK; 
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

            /* Set HTTP GET request as TCP payload */
            unsigned char *payload = (unsigned char *)tcp + (tcp->th_off << 2);
            std::string payload_str = "GET / HTTP/1.1\r\nHost: " + domain + "\r\n\r\n";
            packlen = sizeof(struct tcphdr) + payload_str.length();
            memcpy(payload, payload_str.c_str(), payload_str.length());
        }

        /* set checksum for paris goodness */
        uint16_t crafted_cksum = htons(0xbeef);
        uint16_t fudge = compute_data(tcp->th_sum, crafted_cksum);
        tcp->th_sum = crafted_cksum;

        /* encode first 8 bytes of yarrp payload into lower 64 bits of the source IPv6 address */
        uint64_t high_bits = *(uint64_t*)&outip->ip6_src.s6_addr[0];
        uint32_t id = htonl(0x79727036);
        uint64_t low_bits = set_low_bits(id, config->instance, uint8_t(ttl), fudge);
        low_bits = htobe64(low_bits);
        memcpy(outip->ip6_src.s6_addr, &high_bits, 8);
        memcpy(outip->ip6_src.s6_addr + 8, &low_bits, 8);
    }
}
