#include "tofino/stateful_alu_blackbox.p4"
#include "tofino/intrinsic_metadata.p4"

header_type ethernet_t {
	fields {
	dstAddr : 48;
	srcAddr : 48;
	etherType : 16;
	}
}

header_type ipv4_t {
	fields {
	version : 4;
	ihl : 4;
	diffserv : 8;
	totalLen : 16;
	identification : 16;
	flags : 3;
	fragOffset : 13;
	ttl : 8;
	protocol : 8;
	hdrChecksum : 16;
	srcAddr : 32;
	dstAddr: 32;
	}
} 
parser start {
	//TOFINO: In tofino, the ingress_port meta_data is generated after parser, so nothing is done here.
	return  parse_ethernet;
	
}

#define ETHERTYPE_IPV4 0x0800

header ethernet_t ethernet;

parser parse_ethernet {
	extract(ethernet);
	set_metadata(meta.eth_da,ethernet.dstAddr);
	set_metadata(meta.eth_sa,ethernet.srcAddr);
	return select(latest.etherType) {
		ETHERTYPE_IPV4 : parse_ipv4;
		default: ingress;
	}
}

header ipv4_t ipv4;

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

parser parse_ipv4 {
	extract(ipv4);
	
	//TOFINO: We cannot do calculations in parser
	//set_metadata(meta.tcpLength, ipv4.totalLen - 20);	
	return select(ipv4.protocol) {
		IP_PROT_TCP : parse_tcp;
		default: ingress;
	}
	
}

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 4;
        flags : 8;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

//@pragma pa_fragment egress tcp.checksum
//@pragma pa_fragment egress tcp.urgentPtr
header tcp_t tcp;

parser parse_tcp {
	extract(tcp);
/*
	//set_metadata(meta.tcp_sp, tcp.srcPort);
	//set_metadata(meta.tcp_dp, tcp.dstPort);
	set_metadata(meta.tcp_ack, tcp.ack);
	set_metadata(meta.tcp_psh, tcp.psh);
	set_metadata(meta.tcp_rst, tcp.rst);
	set_metadata(meta.tcp_syn, tcp.syn);
	set_metadata(meta.tcp_fin, tcp.fin);	
	set_metadata(meta.tcp_seqNo, tcp.seqNo);
	//set_metadata(meta.tcp_seqNo_plus1, tcp.seqNo+1);
	//set_metadata(meta.tcp_seqNo_minus1, tcp.seqNo-1);
	set_metadata(meta.tcp_ackNo, tcp.ackNo);	
*/
	return ingress;
}
field_list tcp_checksum_list {
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.diffserv;
    ipv4.protocol;
    tcp.srcPort;
    tcp.dstPort;
    tcp.seqNo;
    tcp.ackNo;
    tcp.dataOffset;
    tcp.res;
    tcp.flags;
    tcp.window;
    tcp.urgentPtr;
    //payload;
}

field_list_calculation tcp_checksum {
    input {
        tcp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field tcp.checksum {
	//TOFINO: We cannot add if here on tofino.
	update tcp_checksum;
}
			
header_type meta_t {
	fields {
		tcpLength : 16;
		eth_da:48;
		eth_sa:48;
		zeros:8;	
	}

}

metadata meta_t meta;

field_list l3_hash_fields {

	ipv4.srcAddr;   
	ipv4.dstAddr;
	ipv4.protocol;
	tcp.srcPort;	

	tcp.dstPort;
}
//get the hash according to the 5-touple of this packet
field_list_calculation tcp_session_map_hash {
	input {
		l3_hash_fields;
	}
	algorithm: crc16;
	output_width: 8;

}


field_list reverse_l3_hash_fields {

    	ipv4.dstAddr;   
	ipv4.srcAddr;
	ipv4.protocol;
	
	tcp.dstPort;	
	tcp.srcPort;


}
//reverse the src address and dst address, src port and dst port, to get the hash of the reply-packet of this packet 
//for example: h1 has a session with h2, according the reverse-hash of packet from h2, we can get the hash of packet from h1.
field_list_calculation reverse_tcp_session_map_hash{
	input {
		reverse_l3_hash_fields;
	}
	algorithm:crc16;
	output_width:8;
	
}	


field_list dstip_hash_fields {
	ipv4.dstAddr;
}

field_list_calculation dstip_map_hash {
	input {
		dstip_hash_fields;
	}
	algorithm:crc16;
	output_width:8;
}


table session_init_table {
	actions { 
		sendback_sa;
	}
}



action sendback_sa()
{
	//subtract(meta.tcpLength,20);
	modify_field(meta.tcpLength,1);
	modify_field(meta.zeros,0);
/*
	modify_field(tcp.syn,1);
	modify_field(tcp.ack,1);
	modify_field(tcp.seqNo,0x0) ;
	
	//modify_field(tcp.ackNo,meta.tcp_seqNo_plus1);
	add(tcp.ackNo,meta.tcp_seqNo,1);
	//add_to_field(tcp.ackNo,1);
	modify_field(ipv4.dstAddr, meta.ipv4_sa);
	modify_field(ipv4.srcAddr, meta.ipv4_da);
	modify_field(tcp.srcPort, meta.tcp_dp);
	modify_field(tcp.dstPort, meta.tcp_sp);
*/
	modify_field(ethernet.dstAddr, meta.eth_sa);
	modify_field(ethernet.srcAddr, meta.eth_da);
		
	modify_field(ig_intr_md_for_tm.ucast_egress_port, ig_intr_md.ingress_port);

}


control ingress {
	apply(session_init_table);

}
control egress {
}

