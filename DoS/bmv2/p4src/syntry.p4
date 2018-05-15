// for syn proxy
#define PROXY_OFF 0
#define PROXY_ON 1
// for tcp flags
#define TCP_FLAG_URG 0x20
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_FIN 0x01
// for clone packets
#define CPU_SESSION 500
// for meter
#define METER_COLOR_GREEN 0
#define METER_COLOR_YELLOW 1
#define METER_COLOR_RED 2

#define FALSE 0
#define TRUE 1

// for heavy hitter count-min sketch
#define HH_CONN_THRESHOLD 100 // doubled
#define HH_SIZE_THRESHOLD 4096
// for no_proxy_table
#define CONN_NOT_EXIST 0
#define CONN_HAS_SYN 1
#define CONN_HAS_ACK 2
#define INVALID 0x0
#define VALID 0x1


#include "headers.p4"
#include "parsers.p4"
#include "hashes.p4"

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
		tcp_ack_no:32;
		tcp_seq_no:32;

		// forward information
        nhop_ipv4 : 32;	// ipv4 next hop
	
		// for control flow
		syn_proxy_status : 1;	// 0 for PROXY_OFF, 1 for PROXY_ON
		to_drop : 1;
		in_black_list : 1;

		// seq# offset  
		seq_no_offset : 32;

		// for syn-cookie
		cookie_key1 : 32;
		cookie_key2 : 32;
		cookie_val1 : 32;	// always use val1 first
		cookie_val2 : 32;

		// for blacklist table
		src_ip_hash_val : 12;
		dst_ip_hash_val : 12;
		src_ip_entry_val : 2;
		dst_ip_entry_val : 2;

		// for check_no_proxy_table
		no_proxy_table_hash_val : 13;
		no_proxy_table_entry_val : 2;

		// for check_syn_proxy_table
		syn_proxy_table_hash_val : 13;
		syn_proxy_table_entry_val : 39;

		// for connection num & packet size detector
		hh_hash_val0 : 8;//perhaps be 16
        hh_hash_val1 : 8;
        hh_size_count_val0 : 32;
        hh_size_count_val1 : 32;
        hh_conn_count_val0 : 32;
        hh_conn_count_val1 : 32; 
	}

}
metadata meta_t meta;

//********METADATA ENDS********



//********REGISTERS********
//********11 * 8192 byte = 88KB in total********
register whitelist_table {
	width : 2;
	instance_count : 4096;
}
register blacklist_table {
	width : 2;
	instance_count : 4096;
}
register no_proxy_table {
	width : 2;
	instance_count : 8192;
}
register syn_proxy_table {
	/*
	|32 bits offset|6 bits port(server port)|1 bit is_valid|
	*/
	width : 39; // 32 bit offset + 6 bit port + 1 bit is_valid
	instance_count : 8192;
}
register hh_size_hashtable0
{
    width: 32;
    instance_count: 256;
}
register hh_size_hashtable1
{
    width:32;
    instance_count:256;
}
register hh_conn_hashtable0
{
    width: 32;
    instance_count: 256;
}
register hh_conn_hashtable1
{
    width:32;
    instance_count:256;
}
counter syn_counter {
	type : packets;
	// static : reply_sa_table;
	static : syn_meter_table;
	instance_count : 1;
}
counter valid_ack_counter {
	type : packets;
	static : confirm_connection_table;
	instance_count : 1;
}
//********REGISTERS ENDS********




action _no_op(){
	no_op();
}

action _drop() {
	modify_field(meta.to_drop, TRUE);
	modify_field(ipv4.dst_addr, 0);
	drop();
}


//********for syn_meter_table********
// {
	meter syn_meter {
		type : packets;
		instance_count : 1;
	}
	action syn_meter_action() {
		// read syn proxy status into metadata
		execute_meter(syn_meter, 0, meta.syn_proxy_status);

		// count: syn packet
		count(syn_counter, 0);
	}
	table syn_meter_table {
		actions {
			syn_meter_action;
		}
	}
// }
//********for check_whitelist_table********
// {
	action read_whitelist_entry_value() {
		modify_field_with_hash_based_offset(meta.src_ip_hash_val, 0, src_ip_hash, 12);
		register_read(meta.src_ip_entry_val, whitelist_table, meta.src_ip_hash_val);
		modify_field_with_hash_based_offset(meta.dst_ip_hash_val, 0, dst_ip_hash, 12);
		register_read(meta.dst_ip_entry_val, whitelist_table, meta.dst_ip_hash_val);
	}
	table check_whitelist_table {
		actions {
			read_whitelist_entry_value;
		}
	}
// }
//********for check_blacklist_table********
// {
	action read_blacklist_entry_value() {
		modify_field_with_hash_based_offset(meta.src_ip_hash_val, 0, src_ip_hash, 12);
		register_read(meta.src_ip_entry_val, whitelist_table, meta.src_ip_hash_val);
		modify_field_with_hash_based_offset(meta.dst_ip_hash_val, 0, dst_ip_hash, 12);
		register_read(meta.dst_ip_entry_val, whitelist_table, meta.dst_ip_hash_val);
	}
	table check_blacklist_table {
		actions {
			read_blacklist_entry_value;
		}
	}
// }
//********for mark_in_blacklist_table********
// {
	action mark_in_blacklist() {
		modify_field(meta.in_black_list, TRUE);
	}
	table mark_in_blacklist_table {
		actions {
			mark_in_blacklist;
		}
	}
// }

//********for check_no_proxy_table********
// {
	action read_no_proxy_table_entry_value() {
		modify_field_with_hash_based_offset(meta.no_proxy_table_hash_val, 0, tcp_five_tuple_hash, 13);
		register_read(meta.no_proxy_table_entry_val, no_proxy_table, meta.no_proxy_table_hash_val);
	}
	table check_no_proxy_table {
		actions {
			read_no_proxy_table_entry_value;
		}
	}
// }
//********for sub_delta_to_seq_table********
// {
	action sub_delta_to_seq() {	
		modify_field(meta.to_drop, FALSE);	
		subtract_from_field(tcp.seq_no, meta.syn_proxy_table_entry_val >> 7);
	}
	table sub_delta_to_seq_table {
		actions {
			sub_delta_to_seq;
		}
	}
// }
//********for add_delta_to_ack_table********
// {
	action add_delta_to_ack() {		
		modify_field(meta.to_drop, FALSE);
		add_to_field(tcp.ack_no, meta.syn_proxy_table_entry_val >> 7);
	}
	table add_delta_to_ack_table {
		actions {
			add_delta_to_ack;
		}
	}
// }
//********for check_syn_proxy_table********
// {
	action read_syn_proxy_table_entry_value() {		
		modify_field_with_hash_based_offset(meta.syn_proxy_table_hash_val, 0, tcp_five_tuple_hash, 13);
		register_read(meta.syn_proxy_table_entry_val, syn_proxy_table, meta.syn_proxy_table_hash_val);
	}
	table check_syn_proxy_table {
		actions {
			read_syn_proxy_table_entry_value;
		}
	}
// }
//********for calculate_syn_cookie_table********
// {
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
//********for check_proxy_status_table********
// {
	action turn_on_proxy() {
		modify_field(meta.syn_proxy_status, PROXY_ON);

	}
	action turn_off_proxy() {
		modify_field(meta.syn_proxy_status, PROXY_OFF);
	}
	table check_proxy_status_table {
		actions {
			turn_on_proxy;
			turn_off_proxy;
			_no_op;
		}
	}
// }
//********for drop_table********
// {
	table drop_table {
		actions {
			_drop;
		}
	}
// }
//********for open_window_table********
// {
	action open_window() {
		modify_field(meta.to_drop, FALSE);
		// set tcp seq# to syn cookie value
		modify_field(meta.seq_no_offset, (meta.syn_proxy_table_entry_val & 0x7fffffff80) >> 7);
		// set seq_no_offset
		// TODO: by default, we reckon tcp.seq_no > cookie_val
		subtract(meta.seq_no_offset, tcp.seq_no, meta.seq_no_offset);
		modify_field(tcp.seq_no, (meta.syn_proxy_table_entry_val & 0x7fffffff80) >> 7);
		// write offset, port, is_Valid into syn_proxy_table
		register_write(syn_proxy_table, meta.syn_proxy_table_hash_val, (meta.seq_no_offset << 7) | (standard_metadata.ingress_port << 1) | 0x1);
	}
	table open_window_table {
		actions {
			open_window;
		}
	}
// }
//********for reply_sa_table********
// {
	action reply_sa() {		
		modify_field(meta.to_drop, FALSE);
		// reply client with syn+ack and a certain seq no, and window size 0
		
		// no need to exchange ethernet values
		// since forward table will do this for us
		// // exchange src-eth, dst-eth
		// modify_field(ethernet.src_addr, meta.eth_da);
		// modify_field(ethernet.dst_addr, meta.eth_sa);
		// exchange src-ip, dst-ip
		modify_field(ipv4.src_addr, meta.ipv4_da);
		modify_field(ipv4.dst_addr, meta.ipv4_sa);
		// exchange src-port, dst-port
		modify_field(tcp.srcPort, meta.tcp_dp);
		modify_field(tcp.dstPort, meta.tcp_sp);
		// set tcp flags: SYN+ACK
		modify_field(tcp.flags, TCP_FLAG_ACK | TCP_FLAG_SYN);
		// set ack# to be seq# + 1
		modify_field(tcp.ack_no, tcp.seq_no + 1);
		// set seq# to be a hash val
		modify_field(tcp.seq_no, meta.cookie_val1);
		// set window to be 0.
		// stop client from transferring data
		modify_field(tcp.window, 0);
		// count: syn packet
		// count(syn_counter, 0);
	}
	table reply_sa_table {
		actions {
			reply_sa;
		}
	}
// }
//********for confirm_connection_table********
// {
	action confirm_connection() {
		// handshake with client finished, start establishing connection with server
		modify_field(meta.to_drop, FALSE);
		// syn_proxy_table : set seq#
		register_write(syn_proxy_table, meta.syn_proxy_table_hash_val, (tcp.ack_no - 1) << 7);
		// set seq# to be seq# - 1 (same as the beginning syn packet seq#)
		modify_field(tcp.seq_no, tcp.seq_no - 1);
		// set flag: syn
		modify_field(tcp.flags, TCP_FLAG_SYN);
		// set ack# 0 (optional)
		modify_field(tcp.ack_no, 0);
		// count: valid ack
		count(valid_ack_counter, 0);
	}
	table confirm_connection_table {
		actions {
			confirm_connection;
		}
	}
// }
//********for mark_no_conn_table********
// {
	action mark_no_conn() {
		modify_field(meta.to_drop, FALSE);
		register_write(no_proxy_table, meta.no_proxy_table_hash_val, CONN_NOT_EXIST);
	}
	table mark_no_conn_table {
		actions {
			mark_no_conn;
		}
	}
// }
//********for mark_has_syn_table********
// {
	action mark_has_syn() {
		modify_field(meta.to_drop, FALSE);
		register_write(no_proxy_table, meta.no_proxy_table_hash_val, CONN_HAS_SYN);
	}
	table mark_has_syn_table {
		actions {
			mark_has_syn;
		}
	}
// }
//********for mark_has_ack_table********
// {
	action mark_has_ack() {
		modify_field(meta.to_drop, FALSE);
		register_write(no_proxy_table, meta.no_proxy_table_hash_val, CONN_HAS_ACK);
		// write into whitelist
		register_write(whitelist_table, meta.src_ip_hash_val, 0x2 | meta.src_ip_entry_val);

	}
	table mark_has_ack_table {
		actions {
			mark_has_ack;
		}
	}
// }
//********for mark_foward_normally_table********
// {
	action mark_foward_normally() {
		modify_field(meta.to_drop, FALSE);
	}
	table mark_foward_normally_table {
		actions {
			mark_foward_normally;
		}
	}
// }
//********for set_size_count_table********
// {
	action pkt_size_count() {
		modify_field_with_hash_based_offset(meta.hh_hash_val0, 0, heavy_hitter_hash0, 8);
		register_read(meta.hh_size_count_val0, hh_size_hashtable0, meta.hh_hash_val0);
		add_to_field(meta.hh_size_count_val0, ipv4.totalLen);
		register_write(hh_size_hashtable0, meta.hh_hash_val0, meta.hh_size_count_val0);

		modify_field_with_hash_based_offset(meta.hh_hash_val1, 0, heavy_hitter_hash1, 8);
		register_read(meta.hh_size_count_val1, hh_size_hashtable1, meta.hh_hash_val1);
		add_to_field(meta.hh_size_count_val1, ipv4.totalLen);
		register_write(hh_size_hashtable1, meta.hh_hash_val1, meta.hh_size_count_val1);
	}

	table set_size_count_table{

		actions{
			pkt_size_count;
		}
	}
// }
//********for pkt_count_inc_table********
// {
	action pkt_count_inc() {
		register_read(meta.hh_conn_count_val0, hh_conn_hashtable0, meta.hh_hash_val0);
		add_to_field(meta.hh_conn_count_val0, 1);
		register_write(hh_conn_hashtable0, meta.hh_hash_val0, meta.hh_conn_count_val0);

		register_read(meta.hh_conn_count_val1, hh_conn_hashtable1, meta.hh_hash_val1);
		add_to_field(meta.hh_conn_count_val1, 1);
		register_write(hh_conn_hashtable1, meta.hh_hash_val1, meta.hh_conn_count_val1);
	}

	table pkt_count_inc_table{
		actions{
			pkt_count_inc;
		}
	}
// }
//********for pkt_count_dec_table********
// {
	action pkt_count_dec() {
		register_read(meta.hh_conn_count_val0, hh_conn_hashtable0, meta.hh_hash_val0);
		subtract_from_field(meta.hh_conn_count_val0, 1);
		register_write(hh_conn_hashtable0, meta.hh_hash_val0, meta.hh_conn_count_val0);

		register_read(meta.hh_conn_count_val1, hh_conn_hashtable1, meta.hh_hash_val1);
		subtract_from_field(meta.hh_conn_count_val1, 1);
		register_write(hh_conn_hashtable1, meta.hh_hash_val1, meta.hh_conn_count_val1);
	}

	table pkt_count_dec_table{
		actions{
			pkt_count_dec;
		}
	}
// }
//********for add_to_blacklist_table********
// {
	action add_to_blacklist() {
		register_write(blacklist_table, meta.src_ip_hash_val, 0x2 | meta.src_ip_entry_val);
	}

	table add_to_blacklist_table{
		actions{
			add_to_blacklist;
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
			ipv4.dst_addr : lpm;
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
		modify_field(ethernet.dst_addr, dmac);
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

// control whitelist {
// 	apply(check_whitelist_table);
// 	if(meta.src_ip_entry_val != 0 or meta.dst_ip_entry_val != 0){
// 		apply(mark_foward_normally_table);
// 	}
// }

control blacklist {
	apply(check_blacklist_table);
	if(meta.src_ip_entry_val != 0 or meta.dst_ip_entry_val != 0){
		apply(mark_in_blacklist_table);
	}
}

control syn_proxy {
	// syn proxy on
	// no need for session check since we use stateless SYN-cookie method

	// whether the packet is an ACK, SYN or SYN+ACK
	// syn-cookie will be used
	// it must be calculated.
	// if it is not one of the three types above, it will be dropped in this table
	apply(check_syn_proxy_table);
	if(meta.syn_proxy_table_entry_val & 0x1 == VALID){
		if(standard_metadata.ingress_port == (meta.syn_proxy_table_entry_val & 0x7e) >> 1){
			// it's from server
			// seq# - delta
			apply(sub_delta_to_seq_table);
		}else {
			// from client
			// ack# + delta
			apply(add_delta_to_ack_table);
		}
	}else {
		if(tcp.flags & (TCP_FLAG_ACK | TCP_FLAG_SYN) == (TCP_FLAG_ACK | TCP_FLAG_SYN)){
			// syn+ack
			apply(open_window_table);
		} else{
			apply(calculate_syn_cookie_table);
			if(tcp.flags & TCP_FLAG_SYN == TCP_FLAG_SYN){
				// has syn but no ack
				// send back syn+ack with special seq#
				apply(reply_sa_table);
			} else if(tcp.flags & TCP_FLAG_ACK == TCP_FLAG_ACK) {
				// has ack but no syn
				// make sure ack# is right
				if(tcp.ack_no == meta.cookie_val1 + 1 or tcp.ack_no == meta.cookie_val2 + 1){
					apply(confirm_connection_table);
				}
			}
		}
	}
}

control conn_filter {
	// writing new logic
	// all packets go through the first register array 'no_proxy_table'(2 bits per entry), entries of which are all set to 00 by default
	// we're gonna use symmetry hash (hash to the same value for packets of both two directions)
	// if the corresponding entry is 01 and the incoming packet is SYN+ACK, then forward normally
	// if the corresponding entry is 01 and the incoming packet is ACK, then write 10 into the corresponding entry and forward
	// if the corresponding entry is 10 then forward it normally (or write 00 if the packet is FIN ?)
	// if the corresponding entry is 00:
	// 		if proxy is off and the incoming packet is SYN, then write 01 into the corresponding entry and forward
	// 		else (proxy is on or incoming packet is not SYN), direct it to syn proxy module
	apply(check_no_proxy_table);
	if(meta.no_proxy_table_entry_val == CONN_NOT_EXIST){
		if(meta.syn_proxy_status == PROXY_ON or tcp.flags & TCP_FLAG_SYN == 0){
			// direct this packet to syn proxy
			syn_proxy();
		}else {
			// write 01 into no_proxy_table
			apply(mark_has_syn_table);
		}
	}else if(meta.no_proxy_table_entry_val == CONN_HAS_SYN){
		if(tcp.flags & (TCP_FLAG_ACK | TCP_FLAG_SYN) == (TCP_FLAG_ACK | TCP_FLAG_SYN)){
			// forward normally
			apply(mark_foward_normally_table);
		}else if (tcp.flags & TCP_FLAG_ACK == TCP_FLAG_ACK){
			// write 10 into no_proxy_table
			apply(mark_has_ack_table);
		}else if(tcp.flags & TCP_FLAG_FIN == TCP_FLAG_FIN){
			apply(mark_no_conn_table);
		}
	}else if(meta.no_proxy_table_entry_val == CONN_HAS_ACK){
		if(tcp.flags & TCP_FLAG_FIN == TCP_FLAG_FIN){
			apply(mark_has_syn_table);
		}else{
			// forward normally
			apply(mark_foward_normally_table);
		}
	}
}
control ingress {
	
	// first count syn packets
	if(tcp.flags ^ TCP_FLAG_SYN == 0){
		// only has syn
		apply(syn_meter_table);
	}
	blacklist();
	if(meta.in_black_list == FALSE){
		// whitelist();
		// if(meta.to_drop == TRUE){
			// check proxy status
			apply(check_proxy_status_table);
			conn_filter();
		// }
		
		if(meta.to_drop == FALSE){
			// packets size count
			apply(set_size_count_table);
			// connection count (for each src ip)
			if(tcp.flags & TCP_FLAG_SYN == TCP_FLAG_SYN){
				// add 1 to count-min sketch
				apply(pkt_count_inc_table);
			} else if(tcp.flags & TCP_FLAG_FIN == TCP_FLAG_FIN){
				// subtract 1 from count-min sketch
				apply(pkt_count_dec_table);
			}
			// TODO: bug. Could add server addr to blacklist
			if((meta.hh_size_count_val0 > HH_SIZE_THRESHOLD and 
				meta.hh_size_count_val1 > HH_SIZE_THRESHOLD)
				or
				(meta.hh_conn_count_val0 > HH_CONN_THRESHOLD and 
				meta.hh_conn_count_val1 > HH_CONN_THRESHOLD)){
				apply(add_to_blacklist_table);
			}
		}else{
			apply(drop_table);
		}
		
		apply(ipv4_lpm_table);
		apply(forward_table);
	}
}



//********for send_frame********
// {
	action rewrite_mac(smac) {
		modify_field(ethernet.src_addr, smac);
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

control egress {
	if(standard_metadata.instance_type == 0){
		// not cloned
		apply(send_frame);
	}
}

