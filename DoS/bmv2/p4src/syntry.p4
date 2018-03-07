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
	set_metadata(meta.in_port, standard_metadata.ingress_port);//
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
	
	set_metadata(meta.ipv4_sa, ipv4.srcAddr);
	set_metadata(meta.ipv4_da, ipv4.dstAddr);
	set_metadata(meta.tcpLength, ipv4.totalLen - 20);	
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
		eth_sa:48;
		eth_da:48;
        ipv4_sa : 32;
        ipv4_da : 32;
        tcp_sp : 16;
        tcp_dp : 16;
        nhop_ipv4 : 32;
        if_ipv4_addr : 32;
        if_mac_addr : 48;
        is_ext_if : 1;
        tcpLength : 16;
        in_port : 8;
		out_port:8;
	
		reply_type:4;//0 drop  1 syn/ack back to h1  02 syn to h2  03 send h2 ack  04 resubmit 05 forward the packet as normal  
		tcp_ack:1;
		tcp_psh:1;
		tcp_rst:1;
		tcp_syn:1;
		tcp_fin:1;
		tcp_seqNo:32;
		tcp_h1seq:32;
		tcp_seqOffset:32;
		tcp_ackNo:32;
		tcp_h2seq:32;
		tcp_ackOffset:32;
		
		tcp_session_map_index :  13;
		dstip_pktcount_map_index: 13;
		tcp_session_id : 16;
		
		dstip_pktcount:32;// how many packets have been sent to this dst IP address	 
	
		tcp_session_is_SYN: 8;// this session has sent a syn to switch
		tcp_session_is_ACK: 8;// this session has sent a ack to switchi
		tcp_session_h2_reply_sa:8;// h2 in this session has sent a sa to switch
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
	output_width:13;
}

field_list dstip_hash_fields {
	ipv4.dstAddr;
}

field_list_calculation dstip_map_hash {
	input {
		dstip_hash_fields;
	}
	algorithm:crc16;
	output_width:13;
}

field_list resubmit_FL {
	standard_metadata;
	meta;	
	
}

register tcp_session_is_SYN {
	width : 8;
	instance_count: 8192;
}

register tcp_session_is_ACK {
	width : 8;
	instance_count: 8192;
}
register tcp_session_h2_reply_sa{
	width : 8;
	instance_count: 8192;
}

register h1_seq{
	width : 32;
	instance_count: 8192;
}

register h2_seq{
	width : 32;
	instance_count: 8192;
}

register dstip_pktcount {
	width : 32; 
	instance_count: 8192;
}

action _drop() {
	drop();
}

//************************************for session_check table************************************
action lookup_session_map()
{//from packet come in through port1
	modify_field_with_hash_based_offset(meta.tcp_session_map_index,0,
										tcp_session_map_hash, 13);
	modify_field_with_hash_based_offset(meta.dstip_pktcount_map_index,0,
											dstip_map_hash,13);
	
	register_read(meta.dstip_pktcount,
				 dstip_pktcount, meta.dstip_pktcount_map_index);

	add_to_field(meta.dstip_pktcount,  1);

	register_write(dstip_pktcount,
				   meta.dstip_pktcount_map_index,
					meta.dstip_pktcount);

	register_read(meta.tcp_session_is_SYN,
				  tcp_session_is_SYN, meta.tcp_session_map_index);
	
	register_read(meta.tcp_session_is_ACK,
				  tcp_session_is_ACK, meta.tcp_session_map_index);

	register_read(meta.tcp_session_h2_reply_sa,
				  tcp_session_h2_reply_sa, meta.tcp_session_map_index);
}

action lookup_session_map_reverse()
{//for packet come in through port2, get the reverse-hash
	modify_field_with_hash_based_offset(meta.tcp_session_map_index,0,
										reverse_tcp_session_map_hash, 13);

	modify_field_with_hash_based_offset(meta.dstip_pktcount_map_index,0,
											dstip_map_hash,13);
	
	register_read(meta.dstip_pktcount,
				 dstip_pktcount, meta.dstip_pktcount_map_index);

	add_to_field(meta.dstip_pktcount,  1);

	register_write(dstip_pktcount,
				   meta.dstip_pktcount_map_index,
					meta.dstip_pktcount);

	register_read(meta.tcp_session_is_SYN,
				  tcp_session_is_SYN, meta.tcp_session_map_index);
	
	register_read(meta.tcp_session_is_ACK,
				  tcp_session_is_ACK, meta.tcp_session_map_index);


	register_read(meta.tcp_session_h2_reply_sa,
				  tcp_session_h2_reply_sa, meta.tcp_session_map_index);
}

table session_check {
	reads {
		meta.in_port:exact;
	}
	actions {
	    _drop;	
		lookup_session_map_reverse;
		lookup_session_map;}
}

//**************************for session_init_table*******************
action init_session()
{
	modify_field(meta.reply_type,1);//1 means forward_table should return a SA to h1i

	register_write(tcp_session_is_SYN, meta.tcp_session_map_index,
					1);
	register_write(tcp_session_is_ACK, meta.tcp_session_map_index,0);

	register_write(tcp_session_h2_reply_sa, meta.tcp_session_map_index,0);

	register_write(h1_seq, meta.tcp_session_map_index,meta.tcp_seqNo);
}

table session_init_table {
	actions { init_session; }
	
}


//*******************for session_complete_table**********************
action complete_session()
{
	modify_field(meta.reply_type,2);// 2 means forward_table should send a syn to h2

	register_write(tcp_session_is_SYN, meta.tcp_session_map_index,
					1);
	register_write(tcp_session_is_ACK, meta.tcp_session_map_index,1);

	register_write(tcp_session_h2_reply_sa, meta.tcp_session_map_index, 0);	

}

table session_complete_table {
	actions { complete_session;}
}

//*******************************for handle_resubmit_table*
action set_resubmit()
{
	modify_field(meta.reply_type, 4);//4 means just resubmit it 
}

table handle_resubmit_table{
	actions 
	{
		set_resubmit;
	}

}

//  ********************************for relay_session_table
//
action relay_session()
{

	modify_field(meta.reply_type,3);//not to drop  we should return a ack to h2 (don't forget to swap the ip and macs 

	register_write(tcp_session_is_SYN, meta.tcp_session_map_index,
					1);
	register_write(tcp_session_is_ACK, meta.tcp_session_map_index,1);

	register_write(tcp_session_h2_reply_sa, meta.tcp_session_map_index, 1);	

	register_write(h2_seq,meta.tcp_session_map_index,meta.tcp_seqNo);

}

table relay_session_table
{
	actions{
		relay_session;
	}	
}

action inbound_transformation()
{
	// seq here by pass
	// ack should extract the initial seq given by switch, here 0ddkk

	register_read(meta.tcp_h2seq,
				  h2_seq, meta.tcp_session_map_index);
	subtract(meta.tcp_ackOffset,meta.tcp_ackNo,0);
	add(meta.tcp_ackNo,meta.tcp_ackOffset,meta.tcp_h2seq);
	modify_field(tcp.ackNo,meta.tcp_ackNo);
        modify_field(ipv4.ttl,32);
}

table inbound_tran_table
{
	actions{
		inbound_transformation;
	}
}

action outbound_transformation()
{
	register_read(meta.tcp_h2seq,
				  h2_seq, meta.tcp_session_map_index);
        subtract(meta.tcp_seqOffset,meta.tcp_seqNo,meta.tcp_h2seq);
        add(meta.tcp_seqNo,meta.tcp_seqOffset,0);
        modify_field(tcp.seqNo,meta.tcp_seqNo);
        modify_field(ipv4.ttl,32);

}

table outbound_tran_table
{
        actions{
                outbound_transformation;
        }
}

//*************************forward_normal_table
action set_forward_normal(port)
{
	modify_field(meta.reply_type, 5);
	modify_field(meta.out_port,port); 
}

table forward_normal_table
{
	reads{
		meta.in_port:exact;
	}
	actions{
		_drop;
		set_forward_normal;
	}
}


//**********for forward_table 
action forward_normal()
{//////05
	
	//There should be seq or ack transform 
	//change src mac and dst mac!!

	modify_field(standard_metadata.egress_spec, meta.out_port);

}

action _resubmit()
{// 04
	resubmit(resubmit_FL);
}

action sendback_sa()
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
}

action sendback_session_construct()
{
	modify_field(tcp.fin,1);
	modify_field(standard_metadata.egress_spec, meta.in_port);
}


action setack(port)
{
	modify_field(tcp.syn,0);
	modify_field(tcp.ack,1);
	modify_field(tcp.seqNo, meta.dstip_pktcount);
	modify_field(standard_metadata.egress_spec, port);
}

action sendh2ack()
{
	modify_field(tcp.syn,0);
	modify_field(tcp.ack,1);
	modify_field(tcp.ackNo, meta.tcp_seqNo);
	add_to_field(tcp.ackNo,1);

	modify_field(tcp.seqNo,meta.tcp_ackNo) ;
	modify_field(ipv4.dstAddr, meta.ipv4_sa);
	modify_field(ipv4.srcAddr, meta.ipv4_da);
	modify_field(tcp.srcPort, meta.tcp_dp);
	modify_field(tcp.dstPort, meta.tcp_sp);
	modify_field(ethernet.dstAddr, meta.eth_sa);
	modify_field(ethernet.srcAddr, meta.eth_da);
		
	modify_field(standard_metadata.egress_spec, meta.in_port);
}

action sendh2syn(port)
{
	modify_field(tcp.syn,1);
	modify_field(tcp.ack,0);
	modify_field(tcp.seqNo, meta.tcp_seqNo);
	add_to_field(tcp.seqNo, -1);
	modify_field(tcp.ackNo,0);
	
	modify_field(standard_metadata.egress_spec,port);
}

//00 noreply  01 syn/ack back to h1  02 syn to h2  03 undifined  04 resubmit 05forward the packet 
table forward_table{
	reads{
		meta.reply_type:exact;
	}

	actions{
		forward_normal;//reply_type:05
		_resubmit;//04
		sendh2ack;// 03
		sendh2syn;//02
		sendback_sa;//01
		sendback_session_construct;
		_drop;//0	
	}
}

control ingress {
	apply(session_check);
	if (meta.tcp_session_is_SYN == 0 and meta.tcp_session_is_ACK == 0 and meta.tcp_session_h2_reply_sa ==0)	
	{
		if (meta.tcp_syn == 1 and meta.tcp_ack == 0)
		{
			apply(session_init_table);
		}
	}
	else if (meta.tcp_session_is_SYN == 1 and meta.tcp_session_is_ACK == 0 and meta.tcp_session_h2_reply_sa == 0)
	{
		if (meta.tcp_syn == 0 and meta.tcp_ack == 1)
		{
			apply(session_complete_table);
		}
	}
	else if (meta.tcp_session_is_SYN == 1 and meta.tcp_session_is_ACK == 1 and meta.tcp_session_h2_reply_sa == 0)
	{
		if (meta.in_port == 2 )//expandability will be too poor
		{
			apply(relay_session_table); //check if it is syn/ack and change the register 
		}	
		else
		{
			//set the reply_type to let forward_table directly resubmit 
			//apply(inbound_tranformation_table);
			apply(handle_resubmit_table);
		}
	}
	else 
	{
		if (meta.in_port == 2 )
		{
			apply(outbound_tran_table);
		}
		else if	(meta.in_port == 1)
		{
			apply(inbound_tran_table);
		}
		apply(forward_normal_table);
	
	}

	apply(forward_table);	
}

control egress {
}

