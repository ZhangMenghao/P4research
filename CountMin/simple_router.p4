#include <core.p4>
#include <v1model.p4>

#include "header.p4"
#include "parser.p4"

const bit<16> MAX_ADDRESS = 0x1F;
const bit<16> THRESHOLD_COUNT = 8;

register<bit<48>>(32w1) last_reset_time;
register<bit<32>>(32w32) hashtable_a0;
register<bit<32>>(32w32) hashtable_a1;
register<bit<32>>(32w32) hashtable_a2;
register<bit<32>>(32w32) hashtable_a3;
register<bit<32>>(32w32) hashtable_b0;
register<bit<32>>(32w32) hashtable_b1;
register<bit<32>>(32w32) hashtable_b2;
register<bit<32>>(32w32) hashtable_b3;
register<bit<1>>(32w1) is_a_active;


control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    action egress_drop() {
        mark_to_drop();
    }
    table send_frame {
        actions = {
            rewrite_mac;
            egress_drop;
            NoAction;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 256;
        default_action = NoAction();
    }
    apply {
        if (hdr.ipv4.isValid()) {
          send_frame.apply();
        }
    }
}

control HashtableUpdate(in register<bit<32>> hashtable,
                        in HashAlgorithm algo,
                        in headers hdr,
                        inout bit<32> bytecount) {
    
    action update_hashtable() {
        /* TODO
        Use a hashfunction and calculate the corresponding address
        of the count-min sketch based on its five-tuple (hdr.ipv4.srcAddr,
        hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort)
        Read the previous contents of that address, add the packet length to
        the previous bytecount, update the register address and keep a
        copy of the value in the metadata.
        */
		bit<32> hashtable_address;
		hash(hashtable_address,
			 algo,
			 32w0,
			 { hdr.ipv4.srcAddr,
			   hdr.ipv4.dstAddr,
			   hdr.ipv4.protocol,
			   hdr.tcp.srcPort,
			   hdr.tcp.dstPort},
			   MAX_ADDRESS);
		hashtable.read(bytecount, hashtable_address);
		bytecount = bytecount + (bit<32>)hdr.ipv4.totalLen;
		hashtable.write(hashtable_address,bytecount);
   
   
    }

    apply {
        if (hdr.ipv4.isValid()) {
            update_hashtable();
        }
    }
}

control HHD(inout headers hdr,
            inout metadata meta,
            inout standard_metadata_t standard_metadata) {


    HashtableUpdate() update_hashtable_a0;
    HashtableUpdate() update_hashtable_a1;
    HashtableUpdate() update_hashtable_a2;
    HashtableUpdate() update_hashtable_a3;
    HashtableUpdate() update_hashtable_b0;
    HashtableUpdate() update_hashtable_b1;
    HashtableUpdate() update_hashtable_b2;
    HashtableUpdate() update_hashtable_b3;
    
    action calculate_age() {
        /* TODO
        Read the last_reset_time register and calculate 
        how long has it been since last reset of sketch A based
        on standard_metadata.ingress_global_timestamp.
        Save the result in meta.hhd.filter_age.
        */
        last_reset_time.read(meta.hhd.filter_age,32w0);
        meta.hhd.filter_age = standard_metadata.ingress_global_timestamp;
    }
   
    action set_threshold(bit<32> threshold) {
        /* TODO
        Copy the threshlod to metamhhd.threshold
        */
        meta.hhd.threshold = threshold;
    }
    
    action set_filter() {
        /* TODO
        Check whether count-min sketch A is active
        and set meta.hhd.is_a_active flag appropriately
        */
        is_a_active.read(meta.hhd.is_a_active, 32w0);
    }

    action heavy_hitter_drop() {
        mark_to_drop();
    }

    action decide_heavy_hitter() {
        /* TODO
        Based on whether A is active and the appropriate
        meta.hhd.value_xx values, decide, whether 
        the packet belongs to a heavy hitter flow or not
        and set meta.hhd.is_heavy_hitter flag.
        */
         if (meta.hhd.is_a_active == 1w1) {
            if (meta.hhd.value_a0 > meta.hhd.threshold &&
                meta.hhd.value_a1 > meta.hhd.threshold &&
                meta.hhd.value_a2 > meta.hhd.threshold &&
                meta.hhd.value_a3 > meta.hhd.threshold) {

                meta.hhd.is_heavy_hitter = 1w1;
            } else {
                meta.hhd.is_heavy_hitter = 1w0;
            }
        } else {
            if (meta.hhd.value_b0 > meta.hhd.threshold &&
                meta.hhd.value_b1 > meta.hhd.threshold &&
                meta.hhd.value_b2 > meta.hhd.threshold &&
                meta.hhd.value_b3 > meta.hhd.threshold) {

                meta.hhd.is_heavy_hitter = 1w1;
            } else {
                meta.hhd.is_heavy_hitter = 1w0;
            }
        }
    }


    table threshold_table {
        key = {
                meta.hhd.filter_age : ternary;
        }

        actions = {
            set_threshold;
        }

        size = THRESHOLD_COUNT;
    }

    table drop_heavy_hitter {
        key = {
                meta.hhd.is_heavy_hitter : exact;
        }

        actions = {
            heavy_hitter_drop;
            NoAction;
        }
        size = 2;
        default_action = NoAction();
    }

    apply {
        calculate_age();
        set_filter();
        threshold_table.apply();
        update_hashtable_a0.apply(hashtable_a0, HashAlgorithm.crc32, hdr, meta.hhd.value_a0);
        update_hashtable_a1.apply(hashtable_a1, HashAlgorithm.crc32_custom, hdr, meta.hhd.value_a1);
        update_hashtable_a2.apply(hashtable_a2, HashAlgorithm.crc16, hdr, meta.hhd.value_a2);
        update_hashtable_a3.apply(hashtable_a3, HashAlgorithm.crc16_custom, hdr, meta.hhd.value_a3);
        update_hashtable_b0.apply(hashtable_b0, HashAlgorithm.crc32, hdr, meta.hhd.value_b0);
        update_hashtable_b1.apply(hashtable_b1, HashAlgorithm.crc32_custom, hdr, meta.hhd.value_b1);
        update_hashtable_b2.apply(hashtable_b2, HashAlgorithm.crc16, hdr, meta.hhd.value_b2);
        update_hashtable_b3.apply(hashtable_b3, HashAlgorithm.crc16_custom, hdr, meta.hhd.value_b3);
        decide_heavy_hitter();
        drop_heavy_hitter.apply();
    }

}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action ingress_drop() {
        mark_to_drop();
    }
    action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        meta.ingress_metadata.nhop_ipv4 = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
    }
    action set_dmac(bit<48> dmac) {
        hdr.ethernet.dstAddr = dmac;
    }
    table ipv4_lpm {
        actions = {
            ingress_drop;
            set_nhop;
            NoAction;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
        default_action = NoAction();
    }
    table forward {
        actions = {
            set_dmac;
            ingress_drop;
            NoAction;
        }
        key = {
            meta.ingress_metadata.nhop_ipv4: exact;
        }
        size = 512;
        default_action = NoAction();
    }
    HHD() hhd;
    apply {
        if (hdr.ipv4.isValid()) {
          ipv4_lpm.apply();
          forward.apply();
          hhd.apply(hdr, meta, standard_metadata);
        }
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
