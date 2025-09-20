/****************************************************************************
   Program:     $Id: trace.cpp 39 2015-12-30 20:28:36Z rbeverly $
   Date:        $Date: 2015-12-30 12:28:36 -0800 (Wed, 30 Dec 2015) $
   Description: traceroute class
****************************************************************************/
#include "yarrp.h"

Traceroute::Traceroute(YarrpConfig *_config, Stats *_stats) : config(_config), stats(_stats), tree(NULL), recv_thread()
{
    dstport = config->dstport;
    if (config->ttl_neighborhood)
      initHisto(config->ttl_neighborhood);
    gettimeofday(&start, NULL);
    debug(HIGH, ">> Traceroute engine started: " << start.tv_sec);
    // RFC2822 timestring
    struct tm *p = localtime(&(start.tv_sec));
    char s[1000];
    strftime(s, 1000, "%a, %d %b %Y %T %z", p);
    config->set("Start", s, true);
    pthread_mutex_init(&recv_lock, NULL);
}

Traceroute::~Traceroute() {
    gettimeofday(&start, NULL);
    debug(HIGH, ">> Traceroute engine stopped: " << start.tv_sec);
    fflush(NULL);
    pthread_cancel(recv_thread);
    if (config->out)
        fclose(config->out);

    clearHisto();
}

void
Traceroute::initHisto(uint8_t ttl) {
    cout << ">> Init TTL histogram for neighborhood: " << int(ttl) << endl;
    for (int i = 0; i <= ttl; i++) {
        TTLHisto *t = NULL;
        if (config->ipv6)
            t = new TTLHisto6();
        else
            t = new TTLHisto4();
        ttlhisto.push_back(t);
    }
}

void
Traceroute::clearHisto() {
    vector<TTLHisto* >::iterator it;
    for(it = ttlhisto.begin(); it != ttlhisto.end(); it++) {
        if(*it != NULL) {
            delete *it;
        }
    }
    ttlhisto.clear();
}

void
Traceroute::dumpHisto() {
    if (ttlhisto.size() == 0) 
        return;
    cout << ">> Dumping TTL Histogram:" << endl;
    for (int i = 1; i < ttlhisto.size(); i++) {
        TTLHisto *t = ttlhisto[i];
        cout << "\tTTL: " << i << " ";
        t->dump();
    }
}

uint32_t
Traceroute::elapsed() {
    gettimeofday(&now, NULL);
    if (config->coarse)
        return tsdiff(&now, &start);
    return tsdiffus(&now, &start); 
}

void
Traceroute::lock() {
    pthread_mutex_lock(&recv_lock);
}

void
Traceroute::unlock() {
    pthread_mutex_unlock(&recv_lock);
}


void Traceroute::set_ack_msb_to_ttl_instance_id(struct tcphdr *tcp_hdr, uint8_t ttl, uint8_t instance_id) {
    const uint32_t TTL_MASK = 0b111111u << 26;
    const uint32_t INSTANCE_ID_MASK = 0xFFu << 18;

    uint32_t ack_num = ntohl(tcp_hdr->th_ack);

    // Clear all bits in the first 14 positions, and keep the last 18 bits as is
    ack_num &= ~(TTL_MASK | INSTANCE_ID_MASK);

    ack_num |= ((ttl & 0x3F) << 26); //Only take first 6 bits from ttl
    ack_num |= (((instance_id) & 0xFF) << 18); 

    tcp_hdr->th_ack = htonl(ack_num);
}
