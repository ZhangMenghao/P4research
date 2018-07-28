3/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> MAX_BUCKET = 10000;
const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TCP = 0x06;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<6>  res;
    bit<6>  flags;
    bit<16> window;
    bit<16> tcpChecksum;
    bit<16> urgentPtr;
}

struct metadata {
    ip4Addr_t midDestIp;
    ip4Addr_t nextHop;
    bit<16> bucketIndex;
    bit<16> tcpLength;
}

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    tcp_t       tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        meta.tcpLength = hdr.ipv4.totalLen - 20;
        packet.extract(hdr.tcp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

register<bit<32>>(MAX_BUCKET) activeFlowCount;

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop();
    }

    action calculateBucketIndex() {
        hash(meta.bucketIndex,
            HashAlgorithm.crc32,
            32,
            { hdr.ipv4.srcAddr},
            MAX_BUCKET
        );
    }

    action setAnotherMidHop(ip4Addr_t midHopAddr) {
        meta.midDestIp = midHopAddr;
    }
    action setDefaultMidHop() {
        meta.midDestIp = hdr.ipv4.dstAddr;
        // increment active flow count if it's a SYN
        bit<32> flowCount;
        activeFlowCount.read(flowCount, meta.bucketIndex);
        if(hdr.tcp.flags == 0x02){
            // TCP SYN
            flowCount = flowCount + 2;
            activeFlowCount.write(meta.bucketIndex, flowCount);
        }else if(hdr.tcp.flags == 0x01){
            // TCP FIN
            flowCount = flowCount - 1;
            activeFlowCount.write(meta.bucketIndex, flowCount);
        }
    }

    table checkBucket {
        key = {
            meta.bucketIndex: exact;
        }
        actions = {
            setAnotherMidHop;
            setDefaultMidHop;
        }
        default_action = setDefaultMidHop();
    }


    action set_nhop(ip4Addr_t nextHop) {
        meta.nextHop = nextHop;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            meta.midHopAddr: lpm;
        }
        actions = {
            set_nhop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action set_dmac(macAddr_t dmac, egressSpec_t port) {
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
    }

    table forward_table {
        key = {
            meta.nextHop: exact;
        }
        actions = {
            set_dmac;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.tcp.isValid()) {
            calculateBucketIndex();
            checkBucket.apply();
            ipv4_lpm.apply();
            forward_table.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action rewrite_mac(macAddr_t smac) {
        hdr.ethernet.srcAddr = smac;
    }

    table send_frame {
        key = {
            standard_metadata.egress_spec: exact;
        }
        actions = {
            rewrite_mac;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.tcp.isValid()) {
            send_frame.apply();
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.tcp.isValid(),
            {
                hdr.ipv4.srcAddr;
                hdr.ipv4.dstAddr;
                8'0;
                hdr.ipv4.protocol;
                meta.tcp_length;
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.res,
                hdr.tcp.flags,
                hdr.tcp.ttl,
                hdr.tcp.window,
                hdr.tcp.urgentPtr
            },
            hdr.tcp.tcpChecksum,
            HashAlgorithm.csum16
        );
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.myTunnel);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
