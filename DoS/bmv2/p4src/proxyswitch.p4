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


#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD
header ethernet_t ethernet;



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




header_type tcp_t {
	fields {
		srcPort : 16;
		dstPort : 16;
		seqNo : 32;
		ackNo : 32;
		dataOffset : 4;
        res : 4;
        flags : 3;
		ack: 1;
		psh: 1;
		rst: 1;
		syn: 1;
		fin: 1;		 
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header tcp_t tcp;



parser start {
	set_metadata(meta.in_port, standard_metadata.ingress_port);//
	return  parse_ethernet;
}
parser parse_ethernet {
	extract(ethernet);
	set_metadata(meta.eth_da,ethernet.dstAddr);
	set_metadata(meta.eth_sa,ethernet.srcAddr);
	return select(latest.etherType) {
		ETHERTYPE_IPV4 : parse_ipv4;
		default: ingress;
	}
}
parser parse_ipv4 {
	extract(ipv4);

	set_metadata(meta.ipv4_sa, ipv4.srcAddr);
	set_metadata(meta.ipv4_da, ipv4.dstAddr);
	set_metadata(meta.tcpLength, ipv4.totalLen - 20);	

		return select(ipv4.protocol) {
		IP_PROT_TCP : parse_tcp;
		default: ingress;
	}
}

parser parse_tcp {
	extract(tcp);
	set_metadata(meta.tcp_sp, tcp.srcPort);
	set_metadata(meta.tcp_dp, tcp.dstPort);
	set_metadata(meta.tcp_ack, tcp.ack);
	set_metadata(meta.tcp_psh, tcp.psh);
	set_metadata(meta.tcp_rst, tcp.rst);
	set_metadata(meta.tcp_syn, tcp.syn);
	set_metadata(meta.tcp_fin, tcp.fin);	
	set_metadata(meta.tcp_seqNo, tcp.seqNo);
	set_metadata(meta.tcp_ackNo, tcp.ackNo);	
	return ingress;
}
field_list tcp_checksum_list {
        ipv4.srcAddr;
        ipv4.dstAddr;
        8'0;
        ipv4.protocol;
        meta.tcpLength;
        tcp.srcPort;
        tcp.dstPort;
        tcp.seqNo;
        tcp.ackNo;
        tcp.dataOffset;
        tcp.res;
        tcp.flags;
		tcp.ack;
		tcp.psh;
		tcp.rst;
		tcp.syn;
		tcp.fin;		 
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

header_type meta_t {
	fields {

		in_port : 8;

		eth_sa:48;
		eth_da:48;

		ipv4_sa : 32;
        ipv4_da : 32;
		tcpLength : 16;

		tcp_sp : 16;
        tcp_dp : 16;
		tcp_ack:1;
		tcp_psh:1;
		tcp_rst:1;
		tcp_syn:1;
		tcp_fin:1;
		tcp_seqNo:32;
		tcp_ackNo:32;
		tcp_session_state:8;//0 no packet before; 1 send syn ;2 back syn/ack; 3sent ack 
		whitelist_state:8;
		tcp_session_map_index:13;
		whitelist_map_index:13;
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
	output_width: 13;

}

field_list_calculation whitelist_map_hash {

	input {
		l3_hash_fields;
	}
	algorithm:crc16;
	output_width:13;
}

register whitelist{
	width:8;
	instance_count:8192;
}

register tcp_session_state {
	width:8;
	instance_count:8192;
}
register debug {
	width:16;
	instance_count :20;
}
action _drop() {
	drop();
}
table drop_table{
	actions {
		_drop;
	}
}
action lookup_whitelist()
{
	modify_field_with_hash_based_offset(meta.whitelist_map_index, 0,
										whitelist_map_hash,13);
	register_read(meta.whitelist_state,
				  whitelist,
				  meta.whitelist_map_index );

	modify_field_with_hash_based_offset(meta.tcp_session_map_index,0,
									tcp_session_map_hash, 13);
	modify_field(tcp.ackNo,meta.tcp_seqNo);
	add_to_field(tcp.ackNo,1);

	register_read(meta.tcp_session_state,
					tcp_session_state,
					meta.tcp_session_map_index);
		
	

}
table whitelist_check_table {

	actions {
		lookup_whitelist;
		
	}
}

action forward_normal(port)
{//need to modify src mac  dst mac and ip.ttl 
//https://github.com/p4lang/tutorials/blob/master/SIGCOMM_2017/exercises/basic/solution/basic.p4
	modify_field(standard_metadata.egress_spec,port);
}

table forward_normal_table {
	reads{
		meta.in_port:exact;//maybe read mac or ip(midify ttl .etc) to select port
	}
	actions{
		_drop;
		forward_normal;
	}
}
action sendBackSynAck()
{
	modify_field(tcp.syn,1);
	modify_field(tcp.ack,1);
	modify_field(tcp.seqNo,0x0) ;
	
	modify_field(tcp.ackNo,meta.tcp_seqNo);
	add_to_field(tcp.ackNo,1);
	modify_field(ipv4.dstAddr, meta.ipv4_sa);
	modify_field(ipv4.srcAddr, meta.ipv4_da);
	modify_field(tcp.srcPort, meta.tcp_dp);
	modify_field(tcp.dstPort, meta.tcp_sp);
	modify_field(ethernet.dstAddr, meta.eth_sa);
	modify_field(ethernet.srcAddr, meta.eth_da);
		
	modify_field(standard_metadata.egress_spec, meta.in_port);


	register_write(tcp_session_state, meta.tcp_session_map_index,
		1);
}
table session_init_table {

	actions {
		
		sendBackSynAck;
	}

}

action sendBackRst()
{
//	modify_field(tcp.syn,1);
	modify_field(tcp.rst,1);
//	modify_field(tcp.seqNo,0x0) ;
	
	// modify_field(tcp.ackNo,meta.tcp_seqNo);
	// add_to_field(tcp.ackNo,1);
	modify_field(ipv4.dstAddr, meta.ipv4_sa);
	modify_field(ipv4.srcAddr, meta.ipv4_da);
	modify_field(tcp.srcPort, meta.tcp_dp);
	modify_field(tcp.dstPort, meta.tcp_sp);
	modify_field(ethernet.dstAddr, meta.eth_sa);
	modify_field(ethernet.srcAddr, meta.eth_da);
		
	modify_field(standard_metadata.egress_spec, meta.in_port);


	register_write(tcp_session_state, meta.tcp_session_map_index,
		2);
	register_write(whitelist,meta.whitelist_map_index,1);
}
table session_construct_table {

	actions {
		sendBackRst;
	}
}
control ingress {
	apply(whitelist_check_table);
	if (ethernet.etherType != ETHERTYPE_IPV4 or ipv4.protocol != IP_PROT_TCP or 
	meta.whitelist_state == 1)
	{
		apply(forward_normal_table);
	}
	
	else
	{
		if (meta.tcp_syn == 1 and meta.tcp_ack == 0 and meta.tcp_session_state == 0 )
		{
			//sendback syn/ack
			apply(session_init_table);

		}
		// else if (meta.tcp_syn == 1 && meta.tcp_ack == 1 && meta.session_state == 1)
		// {
			
		// 	//send back ack
		// }
		else if (meta.tcp_syn == 0 and meta.tcp_ack == 1 and meta.tcp_session_state == 1)
		{//verify the ack num  and RST
			if (meta.tcp_ackNo == 0x1)
			{
				apply(session_construct_table);
			}
		}
		else{
			apply(drop_table);
		}

	}
	
	
}
control egress{
	
}