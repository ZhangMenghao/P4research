#ifndef __HEADER_P4__
#define __HEADER_P4__ 1

struct ingress_metadata_t {
    bit<32> nhop_ipv4;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> hdrLength;
    bit<16> checksum;
}

struct hhd_t {
    @name("filter_age")
    bit<48> filter_age;
    bit<32> value_a0;
    bit<32> value_a1;
    bit<32> value_a2;
    bit<32> value_a3;
    bit<32> value_b0;
    bit<32> value_b1;
    bit<32> value_b2;
    bit<32> value_b3;
    bit<32> threshold;
    bit<1>  is_a_active;
    bit<1>  is_heavy_hitter;
}

struct metadata {
    @name("ingress_metadata")
    ingress_metadata_t   ingress_metadata;
    @name("hhd")
    hhd_t hhd;
}

struct headers {
    @name("ethernet")
    ethernet_t ethernet;
    @name("ipv4")
    ipv4_t     ipv4;
	@name("tcp")
	tcp_t tcp;
	@name("udp")
	udp_t udp;
}

#endif // __HEADER_P4__
