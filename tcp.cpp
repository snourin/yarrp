#include "yarrp.h"

TCP::TCP() :
    sport(0), dport(0), ipid(0), ttl(0), ttl_triggered(0), payload_len(0),
    total_len(0), seq(0), ack(0), flags(0), window(0), checksum(0), urg_ptr(0)
{
    gettimeofday(&tv, NULL);
}

TCP::~TCP() {

}

TCP4::TCP4(struct ip *ip_hdr, struct tcphdr *tcp_hdr) {
    sport = ntohs(tcp_hdr->th_sport);
    dport = ntohs(tcp_hdr->th_dport);
    ttl = ip_hdr->ip_ttl;
    ipid = ntohs(ip_hdr->ip_id);
    seq = ntohl(tcp_hdr->th_seq);
    ack = ntohl(tcp_hdr->th_ack);
    flags = tcp_hdr->th_flags;
    window = ntohs(tcp_hdr->th_win);
    checksum = ntohs(tcp_hdr->th_sum);
    urg_ptr = ntohs(tcp_hdr->th_urp);

    unsigned int ip_hdr_len = ip_hdr->ip_hl << 2;
    unsigned int tcp_hdr_len = tcp_hdr->th_off << 2;

    total_len = ntohs(ip_hdr->ip_len) - ip_hdr_len;
    payload_len = total_len - tcp_hdr_len;

    ttl_triggered = seq;
}

TCP6::TCP6(struct ip6_hdr *ip6_header, struct tcphdr *tcp_hdr) {
    sport = ntohs(tcp_hdr->th_sport);
    dport = ntohs(tcp_hdr->th_dport);
    ttl = ip6_header->ip6_hlim;
    seq = ntohl(tcp_hdr->th_seq);
    ack = ntohl(tcp_hdr->th_ack);
    flags = tcp_hdr->th_flags;
    window = ntohs(tcp_hdr->th_win);
    checksum = ntohs(tcp_hdr->th_sum);
    urg_ptr = ntohs(tcp_hdr->th_urp);

    unsigned int tcp_hdr_len = tcp_hdr->th_off << 2;

    total_len = ntohs(ip6_header->ip6_plen);
    payload_len = total_len - tcp_hdr_len;

    ttl_triggered = seq;
}

void TCP::print(char *src, char *dst) {
    printf("\tFrom: %s -> To: %s\n", src, dst);
    printf("\tTS: %lu.%ld\n", tv.tv_sec, (long) tv.tv_usec);
    printf("\tSrc Port: %u Dst Port: %u\n", sport, dport);
    printf("\tProbe TTL: %d\n", ttl);
    printf("\tProbe IPID: %u\n", ipid);
    printf("\tSeq No: %u Ack No: %u\n", seq, ack);
    printf("\tFlags: 0x%02x\n", flags);
    printf("\tPayload Len: %d Total Len: %d\n", payload_len, total_len);
    printf("\tTTL Triggered: %d\n", ttl_triggered);
    printf("\nWindow: %u Checksum: %u Urg Ptr: %u\n", window, checksum, urg_ptr);
}

void TCP4::print() {
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_src, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_dst, dst, INET_ADDRSTRLEN);

    if (verbosity > HIGH) {
        printf(">> TCP Response:\n");
        TCP::print(src, dst);
    } else if (verbosity > LOW) {
        printf("TCP4 %s -> %s  [%u -> %u] SEQ: %u ACK: %u FLAGS: 0x%02x\n", src, dst, sport, dport, seq, ack, flags);
    }
}

void TCP6::print() {
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip_src, src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip_dst, dst, INET6_ADDRSTRLEN);

    if (verbosity > HIGH) {
        printf(">> TCP6 Response:\n");
        TCP::print(src, dst);
    } else if (verbosity > LOW) {
        printf("TCP6 %s -> %s  [%u -> %u] SEQ: %u ACK: %u FLAGS: 0x%02x\n", src, dst, sport, dport, seq, ack, flags);
    }

}

/* trgt, sec, usec, sport, dport, ttl, ipid, src, seq, ack, flags, payload_len, total_len, ttl_triggered, window, checksum, urg_ptr, count */
void TCP::write(FILE ** out, char *src, char *target) {
    if (*out == NULL)
        return;
    fprintf(*out, "%s %lu %ld %d %d ",
        target, tv.tv_sec, (long) tv.tv_usec, sport, dport);
    fprintf(*out, "%u %u %s %u %u ",
        ttl, ipid, src, seq, ack);
    fprintf(*out, "%d %d %d %d ",
        flags, payload_len, total_len, ttl_triggered);
    fprintf(*out, "%u %u %u\n", window, checksum, urg_ptr);
    // fprintf(*out, "%d\n", count);
}

void TCP4::write(FILE ** out) {
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_src, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_dst, dst, INET_ADDRSTRLEN);
    TCP::write(out, src, dst);
}

void TCP6::write(FILE ** out) {
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip_src, src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip_dst, dst, INET6_ADDRSTRLEN);
    TCP::write(out, src, dst);
}