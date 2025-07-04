class TCP {
    public:
    TCP();
    ~TCP();
    virtual void print() {};
    virtual void write(FILE **) {};
    virtual uint32_t getSrc() { return 0; };
    virtual struct in6_addr *getSrc6() { return NULL; };
    virtual uint32_t getDst() { return 0; };
    virtual struct in6_addr *getDst6() { return NULL; };
    uint16_t getSPort() { return sport; }
    uint16_t getDPort() { return dport; }
    uint16_t getIPID() { return ipid; }
    uint32_t getTTL() { return ttl; }
    uint32_t getTTLTriggered() { return ttl_triggered; }
    uint16_t getPayloadLen() { return payload_len; }
    uint16_t getTotalLen() { return total_len; }
    uint32_t getSeq() { return seq; }
    uint32_t getAck() { return ack; }
    uint8_t getFlags() { return flags; }
    uint16_t getWindow() { return window; }
    uint16_t getChecksum() { return checksum; }
    uint16_t getUrgPtr() { return urg_ptr; }
    void print(char *, char *);
    void write(FILE **, char *, char *);

    protected:
    uint16_t sport;
    uint16_t dport;
    uint16_t ipid;
    uint32_t ttl;
    uint32_t ttl_triggered;
    uint16_t payload_len;
    uint16_t total_len;
    uint32_t seq;
    uint32_t ack;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
    struct timeval tv;
};

class TCP4: public TCP {
    public:
    TCP4(struct ip *, struct tcphdr *);
    uint32_t getSrc() { return ip_src.s_addr; }
    uint32_t getDst() { return ip_dst.s_addr; }
    void print();
    void write(FILE **);

    private:
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

class TCP6: public TCP {
    public:
    TCP6(struct ip6_hdr *, struct tcphdr *);
    struct in6_addr *getSrc6() { return &ip_src; }
    struct in6_addr *getDst6() { return &ip_dst; }
    void print() override;
    void write(FILE **);

    private:
    struct in6_addr ip_src;
    struct in6_addr ip_dst;

};
