#include "includes/headers.p4"
#include "includes/parsers.p4"
#define HHTHRESHOLD 4096
field_list ipv4_checksum_list {
    ipv4.version;
    ipv4.ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation ipv4_checksum{
    input {
        ipv4_checksum_list;
    }
    algorithm: csum16;
    output_width:16;
}
calculated_field ipv4.hdrChecksum {
    verify ipv4_checksum;
    update ipv4_checksum;
}

action _drop()
{
    drop();
}

header_type custom_metadata_t {
    fields{
        nhop_ipv4:32;
        hash_val0:8;//perhaps be 16
        hash_val1:8;
        count_val0:32;
        count_val1:32;
        totalLength:32;

        //TODO: add the meta for hash
    }
}

metadata custom_metadata_t custom_metadata;

action set_nhop(nhop_ipv4,port)
{
    modify_field(custom_metadata.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
    add_to_field(ipv4.ttl,-1);
}

action set_dmac(dmac)
{
    modify_field(ethernet.dstAddr,dmac);
}


field_list hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
}
field_list_calculation heavy_hitter_hash0{
    input {
        hash_fields;
    }
    algorithm:csum16;
    output_width:8;
}
field_list_calculation heavy_hitter_hash1{
    input{
        hash_fields;
    }
    algorithm:crc16;
    output_width:8;
}

register hashtable0
{
    width: 32;
    instance_count: 256;
}
register hashtable1
{
    width:32;
    instance_count:256;
}
// register hashtable2
// {
//     width:32;
//     instance_count:128;
// }
// register hashtable3
// {
//     width:32;
//     instance_count:128;
// }

action set_heavy_hitter_count() {
    modify_field_with_hash_based_offset(custom_metadata.hash_val0, 0,
                                        heavy_hitter_hash0, 8);
    register_read(custom_metadata.count_val0, hashtable0, custom_metadata.hash_val0);
    add_to_field(custom_metadata.count_val0, ipv4.totalLen);
    register_write(hashtable0, custom_metadata.hash_val0, custom_metadata.count_val0);

    modify_field_with_hash_based_offset(custom_metadata.hash_val1, 0,
                                        heavy_hitter_hash1, 8);
    register_read(custom_metadata.count_val1, hashtable1, custom_metadata.hash_val1);
    add_to_field(custom_metadata.count_val1, ipv4.totalLen);
    register_write(hashtable1, custom_metadata.hash_val1, custom_metadata.count_val1);
}

table set_heavy_hitter_count_table{

    actions{
        set_heavy_hitter_count;
    }
    size:1;
}

table drop_heavy_hitter_table {
    actions {
        _drop;
    }
    size:1;
}


table ipv4_lpm_table {

    reads {
        ipv4.dstAddr:lpm;
    }
    actions {
        set_nhop;
        _drop;
    }
    size:1024;
}

table forward_table {
    reads {
        custom_metadata.nhop_ipv4 : exact;
    }
    actions {
        set_dmac;
        _drop;
    }
    size: 512;
}

action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
}

table send_frame_table{
    reads{
        standard_metadata.ingress_port:exact;
    }
    actions {
        rewrite_mac;
        _drop;
    }
    size:256;
}

control ingress {
    apply(set_heavy_hitter_count_table);
    if (custom_metadata.count_val0 > HHTHRESHOLD and 
        custom_metadata.count_val1 > HHTHRESHOLD
       ){ 
        apply(drop_heavy_hitter_table);

    }
    else
    {
        apply(ipv4_lpm_table);
        apply(forward_table);
    }
}

control egress {
    apply(send_frame_table);
}