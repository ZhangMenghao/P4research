// The tofino directory is in p4-compilers-4.1.1.15/p4_lib/tofino/

#include "tofino/stateful_alu_blackbox.p4"
#include "tofino/intrinsic_metadata.p4"
#include "tofino/constants.p4"

#include "include/headers.p4"
#include "include/parser.p4"
#include "include/time.p4"

header_type meta_t {
	fields {
		time32 : 32;
		countt : 16;

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
		tcp_synack:1;
		tcp_psh:1;
		tcp_rst:1;
		tcp_fin:1;
		tcp_seqNo:32;
		tcp_h1seq:32;
		tcp_ackNo:32;
		tcp_h2seq:32;
		tcp_session_map_index :  16;
		reverse_tcp_session_map_index :  16;
		dstip_pktcount_map_index: 8;
		tcp_session_id : 16;
		dstip_pktcount:32;// how many packets have been sent to this dst IP address	 
		tcp_session_is_SYN: 8;// this session has sent a syn to switch
		tcp_session_is_ACK: 8;// this session has sent a ack to switchi
		tcp_session_h2_reply_sa:8;// h2 in this session has sent a sa to switch
		h1_seq : 32;
		over_thres1: 1;
		thres1: 32;
		over_thres2: 1;
		thres2: 32;

		// syn & valid ack counter
		syn_counter_val : 32;
		vack_counter_val : 32;

		// proxy status
		proxy_status : 1;

		// no_proxy_table entry
		no_proxy_table_entry_val : 2;
		
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
	output_width: 16;

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
	output_width:16;
	
}	

// added by kongx
// syn & vack counter
register syn_count_register{
	width : 32;
	instance_count : 1;
}
blackbox stateful_alu read_syn_count{
	reg : syn_count_register;
	update_lo_1_value : register_lo;
	output_value : alu_lo;
	output_dst : meta.syn_counter_val;
}
blackbox stateful_alu write_syn_count{
	reg : syn_count_register;
	update_lo_1_value : meta.syn_counter_val;
	output_value : alu_lo;
	output_dst : meta.syn_counter_val;
}
action syn_count()
{
	read_syn_count.execute_stateful_alu(0);
	modify_field(meta.syn_counter_val, meta.syn_counter_val + 1);
	write_syn_count.execute_stateful_alu(1);
}
table syn_counter_table {
	actions { syn_count;}
}
register vack_count_register{
	width : 32;
	instance_count : 1;
}
blackbox stateful_alu read_vack_count{
	reg : vack_count_register;
	update_lo_1_value : register_lo;
	output_value : alu_lo;
	output_dst : meta.vack_counter_val;
}
blackbox stateful_alu write_vack_count{
	reg : vack_count_register;
	update_lo_1_value : meta.vack_counter_val;
	output_value : alu_lo;
	output_dst : meta.vack_counter_val;
}
action vack_count()
{
	read_vack_count.execute_stateful_alu(0);
	modify_field(meta.vack_counter_val, meta.vack_counter_val + 1);
	write_vack_count.execute_stateful_alu(1);
}
table vack_counter_table {
	actions { vack_count;}
}

action turn_proxy_on()
{
	modify_field(meta.proxy_status, 1);
}
action turn_proxy_off()
{
	modify_field(meta.proxy_status, 0);
}
table check_proxy_status_table{
	actions{
		turn_proxy_on;
		turn_proxy_off;
	}
}
 
register no_proxy_table{
	width : 2;
	instance_count : 65536;
}
blackbox stateful_alu read_no_proxy_entry{
	reg : no_proxy_table;
	update_lo_1_value : register_lo;
        output_value : alu_lo;
        output_dst: meta.no_proxy_table_entry_val;
}
blackbox stateful_alu write_no_proxy_entry{
        reg : no_proxy_table;
        update_lo_1_value : meta.no_proxy_table_entry_val;
        output_value : alu_lo;
        output_dst : meta.no_proxy_table_entry_val;
}
action read_no_proxy_entry()
{
	read_no_proxy_entry.execute_stateful_alu(meta.tcp_session_map_index);
}
table read_no_proxy_entry_table {
	actions { read_no_proxy_entry;}
}
action read_no_proxy_entry_reverse()
{
	read_no_proxy_entry.execute_stateful_alu(meta.reverse_tcp_session_map_index);
}
table read_no_proxy_entry_reverse_table {
	actions { read_no_proxy_entry_reverse;}
}





//TOFINO: We have to separate read and write, because we cannot refer to more than 3 metadata in a SALU.
register h2_seq{
	width : 32;
	instance_count: 65536;
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

action _drop() {
	drop();
}
//************************************for session_check table************************************
action lookup_session_map()
{
	modify_field(meta.in_port,ig_intr_md.ingress_port);
	modify_field_with_hash_based_offset(meta.tcp_session_map_index,0,tcp_session_map_hash, 65536);
}

action lookup_session_map_reverse()
{
	modify_field(meta.in_port,ig_intr_md.ingress_port);
	modify_field_with_hash_based_offset(meta.reverse_tcp_session_map_index,0,reverse_tcp_session_map_hash, 65536);
}
table session_check {
	actions { lookup_session_map;}
}

table session_check_reverse {
	actions { lookup_session_map_reverse;}
}
action read_seq_action(){
	read_h2_seq.execute_stateful_alu(meta.tcp_session_map_index);
	//read_h2_seq.execute_stateful_alu(tcp.srcPort);
}
table read_seq{
	actions {read_seq_action;}
}
action read_seq_action_reverse(){
	read_h2_seq.execute_stateful_alu(meta.reverse_tcp_session_map_index);
	//read_h2_seq.execute_stateful_alu(tcp.dstPort);
}
table read_seq_reverse{
	actions {read_seq_action_reverse;}
}
action write_seq_action(){
	write_h2_seq.execute_stateful_alu(meta.reverse_tcp_session_map_index);
	//write_h2_seq.execute_stateful_alu(tcp.dstPort);
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

action report(){
	generate_digest(FLOW_LRN_DIGEST_RCVR,hash_fields);
}

table report_table
{
	actions{report;}
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

/*** cm sketch ***/

field_list hash_fields {
    ipv4.srcAddr;
}
field_list_calculation heavy_hitter_hash1 {
    input { 
        hash_fields;
    }
    algorithm : crc16;
    output_width : 16;
}

field_list_calculation heavy_hitter_hash2 {
    input { 
        hash_fields;
    }
    algorithm : crc32;
    output_width : 16;
}

register heavy_hitter_counter1{
    width : 32;
    instance_count : 65536;
}

register heavy_hitter_counter2{
    width : 32;
    instance_count : 65536;
}

blackbox stateful_alu cmsketch1{
    reg: heavy_hitter_counter1;
    condition_lo:register_lo-meta.thres1>0;
    update_lo_1_value: register_lo+1;
    output_predicate: condition_lo;
    output_value: combined_predicate;
    output_dst: meta.over_thres1;
    initial_register_lo_value: 0;
}

blackbox stateful_alu cmsketch2{
    reg: heavy_hitter_counter2;
    condition_lo:register_lo-meta.thres2>0;
    update_lo_1_value: register_lo+1;
    output_predicate: condition_lo;
    output_value: combined_predicate;
    output_dst: meta.over_thres2;
    initial_register_lo_value: 0;
}

action set_heavy_hitter_count_1(){
    cmsketch1.execute_stateful_alu_from_hash(heavy_hitter_hash1);
}

action set_heavy_hitter_count_2(){
    cmsketch2.execute_stateful_alu_from_hash(heavy_hitter_hash2);
}

//@pragma stage 1
table set_heavy_hitter_count_table_1 {
    actions {
        set_heavy_hitter_count_1;
    }
    size: 1;
}
//@pragma stage 1
table set_heavy_hitter_count_table_2 {
    actions {
        set_heavy_hitter_count_2;
    }
    size: 1;
}
action nop(){
}
table acl{
	reads {
	   	ipv4.srcAddr : ternary;
	}
	actions {
	        nop;
       		_drop;
       }
}
table init{
	actions{init_action;}
}
action init_action(thres1,thres2){
	modify_field(meta.thres1,thres1);
	modify_field(meta.thres2,thres2);
}

control syn_proxy {


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
	else if (meta.tcp_syn == 0 and meta.tcp_ack == 1 and meta.tcp_h2seq == 0)
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

control conn_filter {
	apply(check_proxy_status_table);

	// calculate index
	if(ig_intr_md.ingress_port == 128){
		apply(session_check);
	}
	else {
		apply(session_check_reverse);
	}

	if (meta.in_port == 128){
		apply(read_no_proxy_entry_table);
	}
	else if (meta.in_port == 136){
		apply(read_no_proxy_entry_reverse_table);
	}
	
	
	if((meta.no_proxy_table_entry_val == 0 and meta.proxy_status == 1)
	or
	(meta.no_proxy_table_entry_val == 0 and meta.tcp_syn == 0)
	or
	(meta.tcp_syn == 1 and meta.proxy_status == 1)){
		apply(mark_no_conn_table);	
		syn_proxy();
	}
	else{
		apply(mark_no_proxy_table);
	} 
}

control ingress {

	apply(update_countt);
	apply(time32_in);
	apply(write_time_in);


	apply(init);
	apply(acl);

	//2-bit
	if(meta.tcp_syn == 1){
		apply(syn_counter_table);
	}
	conn_filter();
	
	apply(set_heavy_hitter_count_table_1);
	apply(set_heavy_hitter_count_table_2);
	if(meta.over_thres1 == 1 and meta.over_thres2 == 1){	
		apply(report_table);
	}
}
control egress {
	apply(time32_eg);
	apply(write_time_eg);
}
