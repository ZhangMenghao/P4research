// The tofino directory is in p4-compilers-4.1.1.15/p4_lib/tofino/

#include "tofino/stateful_alu_blackbox.p4"
#include "tofino/intrinsic_metadata.p4"
#include "include/headers.p4"
#include "include/parser.p4"

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
		tcp_syn:1;
		tcp_ack:1;
		reply_type:4;
		//0 drop  1 syn/ack back to h1  02 syn to h2  03 send h2 ack  04 resubmit 05 forward the packet as normal  
		tcp_synack:1;
		tcp_psh:1;
		tcp_rst:1;
		tcp_fin:1;
		tcp_seqNo:32;
		tcp_h1seq:32;
		tcp_ackNo:32;
		tcp_h2seq:32;
		tcp_session_map_index :  8;
		reverse_tcp_session_map_index :  8;
		dstip_pktcount_map_index: 8;
		tcp_session_id : 16;
		dstip_pktcount:32;// how many packets have been sent to this dst IP address	 
		tcp_session_is_SYN: 8;// this session has sent a syn to switch
		tcp_session_is_ACK: 8;// this session has sent a ack to switchi
		tcp_session_h2_reply_sa:8;// h2 in this session has sent a sa to switch
		h1_seq : 32;
		
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



field_list resubmit_FL {
	standard_metadata;
	meta;	
	
}

register tcp_session_is_SYN {
	//TOFINO: Width cannot be 1 or condition_lo will not be supported
	width : 8;
	instance_count: 256;
}

blackbox stateful_alu read_tcp_session_is_SYN{
	//TOFINO: if syn = 1,write and read;else just read

        reg : tcp_session_is_SYN;
	condition_lo : tcp.syn == 1;
	update_lo_1_predicate:condition_lo;
        update_lo_1_value : 1  ;
	update_lo_2_predicate:not condition_lo;
	update_lo_2_value : register_lo;

        output_value : alu_lo;
        output_dst: meta.tcp_session_is_SYN;
}

register tcp_session_is_ACK {
	width : 8;
	instance_count:256;
}

blackbox stateful_alu read_tcp_session_is_ACK{
        reg : tcp_session_is_ACK;
	condition_lo : tcp.ack == 1;
	update_lo_1_predicate:condition_lo;
        update_lo_1_value : 1 ;
	update_lo_2_predicate:not condition_lo;
	update_lo_2_value : register_lo;
        output_value : alu_lo;
        output_dst: meta.tcp_session_is_ACK;
}
register tcp_session_h2_reply_sa{
	width : 1;
	instance_count: 8192;
}
/*
blackbox stateful_alu read_tcp_session_h2_reply_sa{
        reg : tcp_session_h2_reply_sa;
        update_lo_1_value : register_lo;
        output_value : alu_lo;
        output_dst: meta.tcp_session_h2_reply_sa;
}

blackbox stateful_alu write_tcp_session_h2_reply_sa{
        reg : tcp_session_h2_reply_sa;
        update_lo_1_value :set_bitc;
        output_value : alu_lo;
        output_dst: meta.tcp_session_h2_reply_sa;
}
*/

register h1_seq{
	width : 32;
	instance_count: 256;
}

//TOFINO: We have to separate read and write, because we cannot refer to more than 3 metadata in a SALU.
register h2_seq{
	width : 32;
	instance_count: 256;
}
blackbox stateful_alu read_h2_seq{
	reg : h2_seq;
	update_lo_1_value : register_lo;
        output_value : alu_lo;
        output_dst: meta.tcp_h2seq;
}
blackbox stateful_alu write_h2_seq{
        reg : h2_seq;
        update_lo_1_value : meta.tcp_seqNo;
        output_value : alu_lo;
        output_dst : meta.tcp_h2seq;
}
/*
blackbox stateful_alu inbound_h2_seq{
        reg : h2_seq;
        update_lo_1_value :register_lo;
        output_value : register_lo + tcp.ackNo;
        output_dst: tcp.ackNo;
}

blackbox stateful_alu outbound_h2_seq{
        reg : h2_seq;
        update_lo_1_value :register_lo;
        output_value : tcp.seqNo-register_lo;
        output_dst: tcp.seqNo;
}
*/
register dstip_pktcount {
	width : 32; 
	instance_count: 8192;
}

	

action _drop() {
	drop();
}
//************************************for session_check table************************************
action lookup_session_map()
{
	modify_field(meta.in_port,ig_intr_md.ingress_port);
	modify_field_with_hash_based_offset(meta.tcp_session_map_index,0,tcp_session_map_hash, 8);
}

action lookup_session_map_reverse()
{
	modify_field(meta.in_port,ig_intr_md.ingress_port);
	modify_field_with_hash_based_offset(meta.reverse_tcp_session_map_index,0,reverse_tcp_session_map_hash, 8);
}
table session_check {
	actions { lookup_session_map;}
}

table session_check_reverse {
	actions { lookup_session_map_reverse;}
}
table read_state_SYN {
	actions {read_state_SYN_action; }
}
action read_state_SYN_action(){
	read_tcp_session_is_SYN.execute_stateful_alu(meta.tcp_session_map_index);
}

table read_state_ACK {
	actions {read_state_ACK_action; }
}
action read_state_ACK_action(){
	read_tcp_session_is_ACK.execute_stateful_alu(meta.tcp_session_map_index);
}
table read_state_h2 {
	//if the packet is synack, then write,or read;
	reads {
		tcp.syn:exact;
		tcp.ack:exact;
	}
	actions {	
		read_state_h2_action; 
		write_state_h2_action;
	}
}
action read_state_h2_action(){
	read_h2_seq.execute_stateful_alu(meta.tcp_session_map_index);
}

action write_state_h2_action(){
	write_h2_seq.execute_stateful_alu(meta.reverse_tcp_session_map_index);
}

action read_seq_action(){
	read_h2_seq.execute_stateful_alu(meta.tcp_session_map_index);
}
table read_seq{
	actions {read_seq_action;}
}
action read_seq_action_reverse(){
	read_h2_seq.execute_stateful_alu(meta.reverse_tcp_session_map_index);
}
table read_seq_reverse{
	actions {read_seq_action_reverse;}
}
action write_seq_action(){
	write_h2_seq.execute_stateful_alu(meta.reverse_tcp_session_map_index);
}
table write_seq{
	actions {write_seq_action;}
}




table session_init_table {
	actions { 
		sendback_sa;
	}
}


table session_complete_table {
	actions { 
		sendh2syn;
	}
}


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


table relay_session_table
{
	actions{
		sendh2ack;
	}	

}

action inbound_transformation()
{
	add_to_field(tcp.ackNo,meta.tcp_h2seq);

	//subtract_from_field(tcp.checksum,meta.tcp_h2seq);
	

	modify_field(ipv4.diffserv,meta.tcp_session_map_index);
	modify_field(ipv4.identification,meta.reverse_tcp_session_map_index);

	modify_field(ig_intr_md_for_tm.ucast_egress_port, 136);
}

table inbound_tran_table2
{
	actions{
		inbound_transformation2;
	}
}

action inbound_transformation2()
{
}

table inbound_tran_table
{
	actions{
		inbound_transformation;
	}
}
action outbound_transformation()
{
	subtract_from_field(tcp.seqNo,meta.tcp_h2seq);
	modify_field(ig_intr_md_for_tm.ucast_egress_port, 128);
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

table drop_table
{
	actions{_drop;}
}

//**********for forward_table 
action forward_normal()
{
	modify_field(ig_intr_md_for_tm.ucast_egress_port, meta.out_port);

}
action _resubmit()
{// 04
	//resubmit(resubmit_FL);
}


action sendback_sa()
{
	modify_field(tcp.syn,1);
	modify_field(tcp.ack,1);
	modify_field(tcp.seqNo,0x0) ;
	add_to_field(tcp.checksum,-0x11);	

	add(tcp.ackNo,meta.tcp_seqNo,1);
	//add_to_field(tcp.ackNo,1);
	modify_field(ipv4.dstAddr, meta.ipv4_sa);
	modify_field(ipv4.srcAddr, meta.ipv4_da);
	modify_field(tcp.srcPort, meta.tcp_dp);
	modify_field(tcp.dstPort, meta.tcp_sp);
	modify_field(ethernet.dstAddr, meta.eth_sa);
	modify_field(ethernet.srcAddr, meta.eth_da);
		
	modify_field(ig_intr_md_for_tm.ucast_egress_port, meta.in_port);

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

	add(tcp.ackNo,meta.tcp_h2seq,1);
	modify_field(ipv4.diffserv,meta.tcp_session_map_index);
	modify_field(ipv4.identification,meta.reverse_tcp_session_map_index);
	
	add_to_field(tcp.checksum,1);

	modify_field(tcp.seqNo,meta.tcp_ackNo) ;
	

	modify_field(ipv4.dstAddr, meta.ipv4_sa);
	modify_field(ipv4.srcAddr, meta.ipv4_da);
	modify_field(tcp.srcPort, meta.tcp_dp);
	modify_field(tcp.dstPort, meta.tcp_sp);
	modify_field(ethernet.dstAddr, meta.eth_sa);
	modify_field(ethernet.srcAddr, meta.eth_da);
		

	modify_field(ig_intr_md_for_tm.ucast_egress_port, 136);

}

action sendh2syn()
{
	//flags changing from 0x10 to 0x2, that is 0xe
	modify_field(tcp.syn,1);
	modify_field(tcp.ack,0);
	add(tcp.seqNo,meta.tcp_seqNo,-1);
	modify_field(tcp.ackNo,0);
	//seq and ack both -0x1

	//for testing
	modify_field(ipv4.identification,meta.reverse_tcp_session_map_index);
	modify_field(ipv4.diffserv,meta.tcp_session_map_index);

	add_to_field(tcp.checksum,0x10);
	
	modify_field(ig_intr_md_for_tm.ucast_egress_port, 136);
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
	if(ig_intr_md.ingress_port == 128){
		apply(session_check);
	}
	else {
		apply(session_check_reverse);
	}
/*
	apply(read_state_SYN);

	if(meta.tcp_session_is_SYN == 1) {
		apply(read_state_ACK);
	}
	if(meta.tcp_session_is_ACK == 1){
		apply(read_state_h2);
	}
*/

	if(meta.tcp_syn == 1 and meta.tcp_ack == 1){
		apply(write_seq);
	}
	else if (meta.in_port == 128){
		apply(read_seq);
	}
	else if (meta.in_port == 136){
		apply(read_seq_reverse);
	}

	if (meta.tcp_syn == 1 and meta.tcp_ack == 0)
	{
		apply(session_init_table);
	}
	else if (meta.tcp_syn == 0 and meta.tcp_ack == 1 and meta.tcp_h2seq == 0/* and meta.tcp_session_is_SYN == 1*/)
	{
		apply(session_complete_table);
	}
	else if (meta.tcp_syn == 1 and meta.tcp_ack == 1)
	{
		apply(relay_session_table); 
	}

	else{
		if (meta.in_port == 136 )
		{
			apply(outbound_tran_table);
		}
		else if	(meta.in_port == 128)
		{
			apply(inbound_tran_table);
			//apply(inbound_tran_table2);
		}
	}

}
control egress {
}

