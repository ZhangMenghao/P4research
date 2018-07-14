
//********
//********PARSERS********
//********

// parser: start
parser start {
	set_metadata(meta.to_drop, TRUE);
	set_metadata(meta.in_black_list, FALSE);
	return  parse_ethernet;
}

#define ETHERTYPE_IPV4 0x0800

// parser: ethernet
parser parse_ethernet {
	extract(ethernet);
	set_metadata(meta.eth_da,ethernet.dst_addr);
	set_metadata(meta.eth_sa,ethernet.src_addr);
	return select(latest.etherType) {
		ETHERTYPE_IPV4 : parse_ipv4;
		default: ingress;
	}
}

// checksum: ipv4
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
	ipv4.src_addr;
	ipv4.dst_addr;
}

field_list_calculation ipv4_checksum {
	input {
		ipv4_checksum_list;
	}
	algorithm : csum16;
	output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
	verify ipv4_checksum;
	update ipv4_checksum;
}

#define IP_PROT_TCP 0x06

// parser: ipv4
parser parse_ipv4 {
	extract(ipv4);
	
	set_metadata(meta.ipv4_sa, ipv4.src_addr);
	set_metadata(meta.ipv4_da, ipv4.dst_addr);
	set_metadata(meta.tcp_length, ipv4.totalLen - 20);	
	return select(ipv4.protocol) {
		IP_PROT_TCP : parse_tcp;
		default: ingress;
	}
}

// checksum: tcp
field_list tcp_checksum_list {
        ipv4.src_addr;
        ipv4.dst_addr;
        8'0;
        ipv4.protocol;
        meta.tcp_length;
        tcp.srcPort;
        tcp.dstPort;
        tcp.seq_no;
        tcp.ack_no;
        tcp.dataOffset;
        tcp.res;
        tcp.flags; 
        tcp.window;
        tcp.urgentPtr;
        payload;
}

field_list_calculation tcp_checksum {
    input {
        tcp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field tcp.checksum {
    verify tcp_checksum if(valid(tcp));
    update tcp_checksum if(valid(tcp));
}

// parser: tcp
parser parse_tcp {
	extract(tcp);
	set_metadata(meta.tcp_sp, tcp.srcPort);
	set_metadata(meta.tcp_dp, tcp.dstPort);
	// set_metadata(meta.tcp_flags, tcp.flags);
	set_metadata(meta.tcp_seq_no, tcp.seq_no);
	set_metadata(meta.tcp_ack_no, tcp.ack_no);
	set_metadata(meta.to_drop, TRUE);
	return ingress;
}
//********PARSERS END********