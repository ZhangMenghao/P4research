
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


#define CONN_NOT_EXIST 00
#define CONN_HAS_SYN 01
#define CONN_HAS_ACK 10
#define INVALID 0x0
#define VALID 0x1


//********
//********HEADERS********
//********
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
		seq_no : 32;
		ack_no : 32;
		dataOffset : 4;
        res : 6;
		flags : 6;	 
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

// header cpu_header_t cpu_header;
header ethernet_t ethernet;
header ipv4_t ipv4;
header tcp_t tcp;
//********HEADERS END********



//********
//********PARSERS********
//********

// parser: start
parser start {
	set_metadata(meta.to_drop, TRUE);
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
		tcp_ack_no:32;
		tcp_seq_no:32;

		// tcp 5-tuple hash
		tcp_digest : 13;
		
		// forward information
        nhop_ipv4 : 32;	// ipv4 next hop
	
		// syn meter result (3 colors)
		syn_meter_result : 2;	// METER_COLOR_RED, METER_COLOR_YELLOW, METER_COLOR_GREEN
		syn_proxy_status : 1;	// 0 for PROXY_OFF, 1 for PROXY_ON

		// seq# offset  
		seq_no_offset : 32;

		// for syn-cookie
		cookie_key1 : 32;
		cookie_key2 : 32;
		cookie_val1 : 32;	// always use val1 first
		cookie_val2 : 32;

		// when receiving syn+ack from server
		cookie_val_in_register : 33;
		offset_val_in_register : 33;

		// for check_no_proxy_table
		no_proxy_table_hash_val : 13;
		no_proxy_table_entry_val : 2;

		// for check_syn_proxy_table
		syn_proxy_table_hash_val : 13;
		syn_proxy_table_entry_val : 39;

		to_drop : 1;
	}

}
metadata meta_t meta;


// field_list copy_to_cpu_fields {
// 	standard_metadata;
//     meta;
// }
//********METADATA ENDS********



//********REGISTERS********
//********11 * 8192 byte = 88KB in total********
counter syn_counter {
	type : packets;
	static : reply_sa_table;
	instance_count : 1;
}
counter valid_ack_counter {
	type : packets;
	static : confirm_connection_table;
	instance_count : 1;
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
	output_width : 16;
}

action _no_op(){
	no_op();
}

action _drop() {
	modify_field(meta.to_drop, TRUE);
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
	field_list syn_cookie_key1_list{
		ipv4.srcAddr;
		ipv4.dstAddr;
		tcp.srcPort;
		tcp.dstPort;
		ipv4.protocol;
		meta.cookie_key1;
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
		meta.cookie_key2;
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
		meta.cookie_key1;
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
		meta.cookie_key2;
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
		modify_field(tcp.ack_no, tcp.seq_no + 1);
		// set seq# to be a hash val
		modify_field(tcp.seq_no, meta.cookie_val1);
		// set window to be 0.
		// stop client from transferring data
		modify_field(tcp.window, 0);
		// count: syn packet
		count(syn_counter, 0);
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
	// check proxy status
	apply(check_proxy_status_table);
	conn_filter();
	
	if(meta.to_drop == FALSE){
		// TODO: next steps (detect packet size & num from each source ip)

	}else{
		apply(drop_table);
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

/*
//********for send_to_cpu********
// {
	action do_cpu_encap() {
		// add_header does not work
		// add_header(cpu_header);
		// modify_field(cpu_header.destination, 0xff);
		// modify_field(cpu_header.seq_no_offset, meta.seq_no_offset);
		modify_field(ethernet.dstAddr, 0xffffffffffff);
		modify_field(tcp.seq_no, meta.seq_no_offset);
	}

	table send_to_cpu {
		actions { do_cpu_encap; }
		size : 0;
	}
// }
*/

control egress {
	if(standard_metadata.instance_type == 0){
		// not cloned
		apply(send_frame);
	}else{
		// cloned.
		// sent to cpu
		// apply(send_to_cpu);
	}
}
