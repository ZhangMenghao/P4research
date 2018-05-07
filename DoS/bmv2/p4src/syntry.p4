
// for syn proxy
#define PROXY_OFF 0
#define PROXY_ON 1
// for forward strategy
#define FORWARD_DROP_PKT 0	// drop packet
#define FORWARD_REPLY_CLIENT_SA 1	// reply client with syn+ack and a certain seq no, and window size 0
#define FORWARD_CONNECT_WITH_SERVER 2	// handshake with client finished, start establishing connection with server
#define FORWARD_OPEN_WINDOW 3	// syn+ack from server received. connection established. forward this packet to client
#define FORWARD_CHANGE_SEQ_OFFSET 4 // it is a packet sent by server to client,an offset needs to be added
#define FORWARD_CHANGE_ACK_OFFSET 5 // it is a packet sent by server to client,an offset needs to be added
#define FORWARD_NORMALLY 6	// forward normally
// for tcp flags
#define TCP_FLAG_URG 0x20
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_FIN 0x01
// for clone packets
#define CLONE_NEW_CONNECTION 0
#define CLONE_UPDATE_OFFSET 1
// for meter
#define METER_COLOR_GREEN 0
#define METER_COLOR_YELLOW 1
#define METER_COLOR_RED 2
// for direction judgement
#define FROM_CLIENT 0
#define FROM_SERVER 1

//********
//********HEADERS********
//********
header_type cpu_header_t {
	// totally self-defined header
	// for identifying packets in the control plane
	// every field should be byte-aligned
	// or it will be difficult to read in python
	fields{
		destination : 8;	// identifier. set to 0xff if it will be sent to cpu
		// is_new_connection : 8;
		seq_no_offset : 32;
	}
}

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

header_type tcp_t {
	fields {
		srcPort : 16;
		dstPort : 16;
		seqNo : 32;
		ackNo : 32;
		dataOffset : 4;
        res : 6;
		flags : 6;	 
        window : 16;
        checksum : 16;
        urgentPtr : 16;
		optional : *;
    }
}

header cpu_header_t cpu_header;
header ethernet_t ethernet;
header ipv4_t ipv4;
header tcp_t tcp;
//********HEADERS END********



//********
//********PARSERS********
//********

// parser: start
parser start {
	set_metadata(meta.in_port, standard_metadata.ingress_port);
	return  parse_ethernet;
}

#define ETHERTYPE_IPV4 0x0800

// parser: ethernet
parser parse_ethernet {
	extract(ethernet);
	set_metadata(meta.eth_da,ethernet.dstAddr);
	set_metadata(meta.eth_sa,ethernet.srcAddr);
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

// parser: ipv4
parser parse_ipv4 {
	extract(ipv4);
	
	set_metadata(meta.ipv4_sa, ipv4.srcAddr);
	set_metadata(meta.ipv4_da, ipv4.dstAddr);
	set_metadata(meta.tcp_length, ipv4.totalLen - 20);	
	return select(ipv4.protocol) {
		IP_PROT_TCP : parse_tcp;
		default: ingress;
	}
}

// checksum: tcp
field_list tcp_checksum_list {
        ipv4.srcAddr;
        ipv4.dstAddr;
        8'0;
        ipv4.protocol;
        meta.tcp_length;
        tcp.srcPort;
        tcp.dstPort;
        tcp.seqNo;
        tcp.ackNo;
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
	set_metadata(meta.tcp_seqNo, tcp.seqNo);
	set_metadata(meta.tcp_ackNo, tcp.ackNo);
	// drop as default
	set_metadata(meta.forward_strategy, FORWARD_DROP_PKT);
	return ingress;
}
//********PARSERS END********


//********
//********METADATA********
//********

header_type meta_t {
	fields {
		// ethernet information
		eth_sa:48;		// eth src addr
		eth_da:48;		// eth des addr
		// ip information
        ipv4_sa : 32;	// ipv4 src addr
        ipv4_da : 32;	// ipv4 des addr
		// tcp information
        tcp_sp : 16;	// tcp src port
        tcp_dp : 16;	// tcp des port
        tcp_length : 16;	// tcp packet length
		tcp_ackNo:32;
		tcp_seqNo:32;
		
		// forward information
		forward_strategy : 4;	// 0: drop // 1: syn+ack back to h1 // 02: syn to h2 // 03: send h2 ack // 04: resubmit // 05: forward the packet as normal  
        nhop_ipv4 : 32;	// ipv4 next hop
        in_port : 8;	// in port (of switch)
	
		// syn meter result (3 colors)
		syn_meter_result : 2;	// METER_COLOR_RED, METER_COLOR_YELLOW, METER_COLOR_GREEN
		syn_proxy_status : 1;	// 0 for PROXY_OFF, 1 for PROXY_ON

		// counter of syn packets and valid ack packets
		syn_counter_val : 32;
		valid_ack_counter_val : 32;

		// seq# offset
		seq_no_offset : 32;

		// for syn-cookie
		cookie_key1 : 32;
		cookie_key2 : 32;
		cookie_val1 : 32;
		cookie_val2 : 32;
	}

}
metadata meta_t meta;


field_list copy_to_cpu_fields {
	standard_metadata;
    meta;
}
//********METADATA ENDS********



//********REGISTERS********
//********11 * 8192 byte = 88KB in total********
register syn_proxy_status {
	width : 1;
	instance_count : 1;
}
register syn_counter {
	// type : packets;
	// static : confirm_connection_table;
	width : 32; 
	instance_count : 1;
}
register valid_ack_counter {
	// type : packets;
	// static : valid_connection_table;
	width : 32;
	instance_count : 1;
}
register syn_cookie_pool {
	width : 32;
	instance_count : 8192;	//13 bits
}
//********REGISTERS ENDS********


field_list tcp_five_tuple_list{
	ipv4.srcAddr;
	ipv4.dstAddr;
	tcp.srcPort;
	tcp.dstPort;
	ipv4.protocol;
}
field_list_calculation tcp_five_tuple_hash {
	input {
		tcp_five_tuple_list;
	}
	algorithm : csum16;
	output_width : 13;
}

action _no_op(){
	no_op();
}

action _drop() {
	modify_field(ipv4.dstAddr, 0);
	drop();
}

// action _resubmit()
// {
// 	resubmit(resubmit_FL);
// }


//********for syn_meter_table********
// {
	meter syn_meter {
		type : packets;
		instance_count : 1;
	}
	action syn_meter_action() {
		// read syn proxy status into metadata
		execute_meter(syn_meter, 0, meta.syn_proxy_status);
	}
	table syn_meter_table {
		actions {
			syn_meter_action;
		}
	}
// }
//********for turn_on_proxy_table********
// {
	action turn_on_proxy() {
		register_write(syn_proxy_status, 0, PROXY_ON);
		// read syn proxy status into metadata
		modify_field(meta.syn_proxy_status, PROXY_ON);
	}
	table turn_on_proxy_table {
		actions {
			turn_on_proxy;
		}
	}
// }
//********for turn_off_proxy_table********
// {
	action turn_off_proxy() {
		register_write(syn_proxy_status, 0, PROXY_OFF);
		// read syn proxy status into metadata
		modify_field(meta.syn_proxy_status, PROXY_OFF);
	}
	table turn_off_proxy_table {
		actions {
			turn_off_proxy;
		}
	}
// }


//********for calculate_syn_cookie_table********
// {
	field_list syn_cookie_key1_list{
		ipv4.srcAddr;
		ipv4.dstAddr;
		tcp.srcPort;
		tcp.dstPort;
		ipv4.protocol;
		meta.key1;
	}
	field_list_calculation syn_cookie_key1_calculation {
		input {
			syn_cookie_key1_list;
		}
		algorithm : crc32;
		output_width : 32;
	}


	field_list syn_cookie_key2_list{
		ipv4.srcAddr;
		ipv4.dstAddr;
		tcp.srcPort;
		tcp.dstPort;
		ipv4.protocol;
		meta.key2;
	}
	field_list_calculation syn_cookie_key2_calculation {
		input {
			syn_cookie_key2_list;
		}
		algorithm : crc32;
		output_width : 32;
	}


	field_list syn_cookie_key1_reverse_list{
		ipv4.dstAddr;
		ipv4.srcAddr;
		tcp.dstPort;
		tcp.srcPort;
		ipv4.protocol;
		meta.key1;
	}
	field_list_calculation syn_cookie_key1_reverse_calculation {
		input {
			syn_cookie_key1_reverse_list;
		}
		algorithm : crc32;
		output_width : 32;
	}


	field_list syn_cookie_key2_reverse_list{
		ipv4.dstAddr;
		ipv4.srcAddr;
		tcp.dstPort;
		tcp.srcPort;
		ipv4.protocol;
		meta.key2;
	}
	field_list_calculation syn_cookie_key2_reverse_calculation {
		input {
			syn_cookie_key2_reverse_list;
		}
		algorithm : crc32;
		output_width : 32;
	}
	// use a simpler version of syn-cookie
	// timestamp(for connection timeout), MSS(for ack packet reconstruction) not implemented
	action calculate_syn_cookie_from_client(key1, key2){
		modify_field(meta.cookie_key1, key1);
		modify_field(meta.cookie_key2, key2);
		modify_field_with_hash_based_offset(meta.cookie_val1, 0, syn_cookie_key1_calculation, 32);
		modify_field_with_hash_based_offset(meta.cookie_val2, 0, syn_cookie_key2_calculation, 32);
	}
	action calculate_syn_cookie_from_server(key1, key2){
		modify_field(meta.cookie_key1, key1);
		modify_field(meta.cookie_key2, key2);
		modify_field_with_hash_based_offset(meta.cookie_val1, 0, syn_cookie_key1_reverse_calculation, 32);
		modify_field_with_hash_based_offset(meta.cookie_val2, 0, syn_cookie_key2_reverse_calculation, 32);		
	}
	table calculate_syn_cookie_table {
		reads {
			// for syn & ack, it is definitely from client
			// syn+ack comes from server
			tcp.flags : ternary;
		}
		actions {
			_drop;
			calculate_syn_cookie_from_client;
			calculate_syn_cookie_from_server;
		}
	}
// }

//********for valid_connection_from_server_table********
// {
	action set_passthrough_syn_proxy_from_server(seq_no_offset) {
		modify_field(meta.forward_strategy, FORWARD_CHANGE_SEQ_OFFSET);
		modify_field(meta.seq_no_offset, seq_no_offset);
	}
	action set_passthrough_syn_proxy_from_server_for_new_connection() {
		// syn+ack packet
		modify_field(meta.forward_strategy, FORWARD_OPEN_WINDOW);	
		// set seq_no_offset
		// register_read(meta.seq_no_offset, sa_seq_num_pool, meta.reverse_eight_bit_index);
		modify_field(meta.seq_no_offset, meta.reverse_eight_bit_index);
		subtract(meta.seq_no_offset, tcp.seqNo, meta.seq_no_offset);
		// modify_field(tcp.seqNo, meta.seq_no_offset);
		// modify_field(tcp.seqNo, 999);
		// modify_field(meta.seq_no_offset, 0);
		// update seq# offset in flow table
		clone_ingress_pkt_to_egress(CLONE_UPDATE_OFFSET, copy_to_cpu_fields);
	}
	action set_passthrough_syn_proxy_packet_source(seq_no_offset) {
		modify_field(meta.forward_strategy, FORWARD_CHANGE_ACK_OFFSET);
		modify_field(meta.seq_no_offset, seq_no_offset);
	}
	table valid_connection_table {
		reads {
			ipv4.srcAddr : exact;
			ipv4.dstAddr : exact;
			tcp.srcPort : exact;
			tcp.dstPort : exact;
			tcp.flags : ternary;
		}
		actions {
			_no_op;
			set_passthrough_syn_proxy_packet_source;
			set_passthrough_syn_proxy_from_server;
			set_passthrough_syn_proxy_from_server_for_new_connection;
		}
	}
// }
//********for reply_sa_table********
// {
	action set_reply_sa() {
		modify_field(meta.forward_strategy, FORWARD_REPLY_CLIENT_SA);
		// count: syn packet
		register_read(meta.syn_counter_val, syn_counter, 0);
		add_to_field(meta.syn_counter_val, 1);
		register_write(syn_counter, 0 , meta.syn_counter_val);
	}
	table reply_sa_table {
		actions {
			set_reply_sa;
		}
	}
// }
//********for confirm_connection_table********
// {
	action confirm_connection() {
		// valid ack#
		modify_field(meta.forward_strategy, FORWARD_CONNECT_WITH_SERVER);
		// count: valid ack
		// count(valid_ack_counter, 0);
		register_read(meta.valid_ack_counter_val, valid_ack_counter, 0);
		add_to_field(meta.valid_ack_counter_val, 1);
		register_write(valid_ack_counter, 0 , meta.valid_ack_counter_val);
		// insert connection in flow table
		clone_ingress_pkt_to_egress(CLONE_NEW_CONNECTION, copy_to_cpu_fields);
	}
	table confirm_connection_table {
		actions {
			confirm_connection;
		}
	}
// }
/*
//********for check_syn_and_valid_ack_num_table******
// {
	action check_syn_and_valid_ack_num() {
		// check the difference between
		// the number of syn packets and the number of valid ack
		register_read(meta.syn_counter_val, syn_counter, 0);
		register_read(meta.valid_ack_counter_val, valid_ack_counter, 0);
	}
	table check_syn_and_valid_ack_num_table {
		actions {
			check_syn_and_valid_ack_num;
		}
	}
// }
*/
//********for no_syn_proxy_table********
// {
	action no_syn_proxy_action() {
		// forward every packets normally
		modify_field(meta.forward_strategy, FORWARD_NORMALLY);	
		modify_field(meta.seq_no_offset, 0);
	}
	table no_syn_proxy_table {
		actions {
			no_syn_proxy_action;
		}
	}
// }
//********for insert_connection_table********
// {
	action insert_connection() {
		clone_ingress_pkt_to_egress(CLONE_NEW_CONNECTION, copy_to_cpu_fields);
	}
	table insert_connection_table {
		actions {
			insert_connection;
		}
	}
// }


//********for syn_proxy_forward_table********
// {
	action syn_proxy_forward_drop(){
		modify_field(ipv4.dstAddr, 0);
		drop();
	}
	action syn_proxy_forward_reply_client_sa(){		
		// reply client with syn+ack and a certain seq no, and window size 0
		
		// no need to exchange ethernet values
		// since forward table will do this for us
		// // exchange src-eth, dst-eth
		// modify_field(ethernet.srcAddr, meta.eth_da);
		// modify_field(ethernet.dstAddr, meta.eth_sa);
		// exchange src-ip, dst-ip
		modify_field(ipv4.srcAddr, meta.ipv4_da);
		modify_field(ipv4.dstAddr, meta.ipv4_sa);
		// exchange src-port, dst-port
		modify_field(tcp.srcPort, meta.tcp_dp);
		modify_field(tcp.dstPort, meta.tcp_sp);
		// set tcp flags: SYN+ACK
		modify_field(tcp.flags, TCP_FLAG_ACK | TCP_FLAG_SYN);
		// set ack# to be seq# + 1
		modify_field(tcp.ackNo, tcp.seqNo + 1);
		// set seq# to be a hash val
		modify_field(tcp.seqNo, meta.sa_seq_num);
		// set window to be 0.
		// stop client from transferring data
		modify_field(tcp.window, 0);
	}
	action syn_proxy_forward_connect_with_server(){
		// handshake with client finished, start establishing connection with server
		// set seq# to be seq# - 1 (same as the beginning syn packet seq#)
		modify_field(tcp.seqNo, tcp.seqNo - 1);
		// set flag: syn
		modify_field(tcp.flags, TCP_FLAG_SYN);
		// set ack# 0 (optional)
		modify_field(tcp.ackNo, 0);
		// TODO: drop data!		
	}
	action syn_proxy_forward_open_window(){
		// syn+ack from server received. connection established. forward this packet to client
		subtract_from_field(tcp.seqNo, meta.seq_no_offset);
	}
	action syn_proxy_forward_change_seq_offset(){
		// it is a packet sent by server to client
		// an offset needs to be added to seq#
		subtract_from_field(tcp.seqNo, meta.seq_no_offset);
		// add_to_field(tcp.seqNo, meta.seq_no_offset);	
	}
	action syn_proxy_forward_change_ack_offset(){
		// it is a packet sent by client to server
		// an offset needs to be added to ack#
		add_to_field(tcp.ackNo, meta.seq_no_offset);
		// add_to_field(tcp.seqNo, meta.seq_no_offset);	
	}
	action syn_proxy_forward_normally(){
		// forward normally
		// do nothing		
	}
	// it is not supposed to be a flow table
	table syn_proxy_forward_table{
		reads {
			meta.forward_strategy : exact;
		}
		actions{
			syn_proxy_forward_drop;
			syn_proxy_forward_reply_client_sa;
			syn_proxy_forward_connect_with_server;
			syn_proxy_forward_open_window;
			syn_proxy_forward_change_seq_offset;
			syn_proxy_forward_change_ack_offset;
			syn_proxy_forward_normally;
		}
	}
// }


//********for ipv4_lpm_table********
// {
	action set_nhop(nhop_ipv4, port) {
		modify_field(meta.nhop_ipv4, nhop_ipv4);
		modify_field(standard_metadata.egress_spec, port);
		add_to_field(ipv4.ttl, -1);
	}
	table ipv4_lpm_table {
		reads {
			ipv4.dstAddr : lpm;
		}
		actions {
			set_nhop;
			_drop;
		}
		size: 1024;
	}
// }


//********for forward_table********
// {
	action set_dmac(dmac) {
		modify_field(ethernet.dstAddr, dmac);
	}
	table forward_table {
		reads {
			meta.nhop_ipv4 : exact;
		}
		actions {
			set_dmac;
			_drop;
		}
		size: 512;
	}
// }

control ingress {
	
	// first count syn packets
	if(tcp.flags ^ TCP_FLAG_SYN == 0){
		// only has syn
		apply(syn_meter_table);
		// turn on the switch of syn proxy if syn is too much (fast)
		if(meta.syn_meter_result == METER_COLOR_RED) {
			// i guess red color means large number of syn packets
			apply(turn_on_proxy_table);
		}
	}
	// TODO: timer来改变8位selection的位置
	// select 8 bit for hashing
	// these 8 bits are used in multiple conditions
	apply(eight_bit_index_select_table);
	// check if this connection has been successfully established before
	// if so, ignore syn proxy mechanism
	apply(valid_connection_table);
	if(meta.forward_strategy == FORWARD_DROP_PKT){
		// does not exist in valid_connection_table.
		// check if syn proxy is on
		/*if(meta.syn_proxy_status == PROXY_ON){*/
			// syn proxy on
			// no need for session check since we use stateless SYN-cookie method

			// whether the packet is an ACK, SYN or SYN+ACK
			// syn-cookie will be used
			// it must be calculated.
			// if it is not one of the three types above, it will be dropped in this table
			apply(calculate_syn_cookie_table);

			if(tcp_flags & (TCP_FLAG_ACK | TCP_FLAG_SYN) == (TCP_FLAG_ACK | TCP_FLAG_SYN)){
				// syn+ack
				 
			} else{
				if(tcp_flags & TCP_FLAG_ACK == TCP_FLAG_ACK){
					// has syn but no ack
					// send back syn+ack with special seq#
					apply(reply_sa_table);
				} else if(tcp_flags & TCP_FLAG_SYN == TCP_FLAG_SYN) {
					// has ack but no syn
					// make sure ack# is right
					if(tcp.ackNo == meta.sa_seq_num + 1){
						apply(confirm_connection_table);
					}
				}
			}
			/*
			// check the difference between
			// the number of syn packets and the number of valid ack
			// apply(check_syn_and_valid_ack_num_table);
			
			// if the difference of the two is less than 1/8 of the smaller one
			// we think that the number of syn pkts and valid ack pkts are roughly equal
			// shutdown syn proxy
			if(meta.syn_counter_val >= meta.valid_ack_counter_val){
				if((meta.syn_counter_val - meta.valid_ack_counter_val) > (meta.valid_ack_counter_val >> 3)){
					apply(turn_off_proxy_table);
				}
			}else{
				if((meta.valid_ack_counter_val - meta.syn_counter_val) > (meta.syn_counter_val >> 3)){
					apply(turn_off_proxy_table);
				}
			}
		}else {			
			// syn proxy off
			// forward every packets normally
			apply(no_syn_proxy_table);
			// store all connections while proxy is off
			// in order to avoid collision when proxy is on
			if(tcp.flags & (TCP_FLAG_ACK | TCP_FLAG_SYN) == (TCP_FLAG_ACK | TCP_FLAG_SYN)){
				// insert connection in flow table
				apply(insert_connection_table);
			}
		}
		*/
	}
	apply(syn_proxy_forward_table);	
	if(meta.forward_strategy == FORWARD_NORMALLY){
		// TODO: next steps (detect packet size & num from each source ip)

	}
	apply(ipv4_lpm_table);
    apply(forward_table);
}



//********for send_frame********
// {
	action rewrite_mac(smac) {
		modify_field(ethernet.srcAddr, smac);
	}
	table send_frame {
		reads {
			standard_metadata.egress_port: exact;
		}
		actions {
			rewrite_mac;
			_drop;
		}
		size: 256;
	}
// }

//********for send_to_cpu********
// {
	action do_cpu_encap() {
		// add_header seems useless 
		// add_header(cpu_header);
		// modify_field(cpu_header.destination, 0xff);
		// modify_field(cpu_header.seq_no_offset, meta.seq_no_offset);
		modify_field(ethernet.dstAddr, 0xffffffffffff);
		modify_field(tcp.seqNo, 0xff0000000000 | meta.seq_no_offset);
	}

	table send_to_cpu {
		actions { do_cpu_encap; }
		size : 0;
	}
// }


control egress {
	if(standard_metadata.instance_type == 0){
		// not cloned
		apply(send_frame);
	}else{
		// cloned.
		// sent to cpu
		apply(send_to_cpu);
	}
}

