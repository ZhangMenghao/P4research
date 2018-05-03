/**************************************/
/**************HEADERS*****************/
/**************************************/
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
    }
}

header ethernet_t ethernet;
header ipv4_t ipv4;
header tcp_t tcp;
/************HEADERS END***************/



/**************************************/
/**************PARSERS*****************/
/**************************************/

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

// parser: tcp
parser parse_tcp {
	extract(tcp);
	set_metadata(meta.tcp_sp, tcp.srcPort);
	set_metadata(meta.tcp_dp, tcp.dstPort);
	set_metadata(meta.tcp_flags, tcp.flags);
	set_metadata(meta.tcp_seqNo, tcp.seqNo);
	set_metadata(meta.tcp_ackNo, tcp.ackNo);	
	return ingress;
}
/************PARSERS END***************/


/**************************************/
/**************METADATA****************/
/**************************************/
// for syn proxy
#define PROXY_OFF 1'0
#define PROXY_ON 1'1
// for forward strategy
#define UNKNOWN 2'0
#define FORWARD_DROP_PKT 2'1	// drop packet
#define FORWARD_REPLY_SA 2'2	// reply client with syn+ack and a certain seq no.
#define FORWARD_ESTABLISH_WITH_SERVER 2'3	// handshake with client finished, start establishing connection with server
#define FORWARD_CONNECTION_ESTABLISHED 2'4	// syn+ack from server received. connection established.
#define FORWARD_NORMALLY 2'5	// forward normally
// for tcp flags
#define TCP_FLAG_URG 6'0x20
#define TCP_FLAG_ACK 6'0x10
#define TCP_FLAG_PSH 6'0x08
#define TCP_FLAG_RST 6'0x04
#define TCP_FLAG_SYN 6'0x02
#define TCP_FLAG_FIN 6'0x01

header_type meta_t {
	fields {
		// ethernet information
		// eth_sa:48;		// eth src addr
		// eth_da:48;		// eth des addr
		// ip information
        // ipv4_sa : 32;	// ipv4 src addr
        // ipv4_da : 32;	// ipv4 des addr
		// tcp information
        // tcp_sp : 16;	// tcp src port
        // tcp_dp : 16;	// tcp des port
        // tcp_length : 16;	// tcp packet length
		// tcp_flags : 6;	// tcp flags: urg, ack, psh, rst, syn, fin
		// tcp_h1seq:32;	// 
		// tcp_seqOffset:32;
		// tcp_ackNo:32;
		// tcp_h2seq:32;
		// tcp_ackOffset:32;
		
		// forward information
		forward_strategy : 4;	// 0: drop // 1: syn+ack back to h1 // 02: syn to h2 // 03: send h2 ack // 04: resubmit // 05: forward the packet as normal  
        nhop_ipv4 : 32;	// ipv4 next hop
        // if_ipv4_addr : 32;
        // if_mac_addr : 48;
        // is_ext_if : 1;
        in_port : 8;	// in port (of switch)
		out_port :8;		// out port (of switch)
	
		// syn meter result (3 colors)
		syn_meter_result : 2;	// METER_COLOR_RED, METER_COLOR_YELLOW, METER_COLOR_GREEN
		syn_proxy_status : 1;	// 0 for PROXY_OFF, 1 for PROXY_ON
		// 8 bits index for seq# selection in syn+ack
		eight_bit_index : 8;
		// seq num in syn+ack
		sa_seq_num : 32;

		// counter of syn packets and valid ack packets
		syn_counter_val : 32;
		valid_ack_counter_val : 32;
		
		// tcp_session_map_index :  13;
		// dstip_pktcount_map_index: 13;
		// tcp_session_id : 16;
		
		// dstip_pktcount:32;// how many packets have been sent to this dst IP address	 
	
		// tcp_session_is_SYN: 8;// this session has sent a syn to switch
		// tcp_session_is_ACK: 8;// this session has sent a ack to switchi
		// tcp_session_h2_reply_sa:8;// h2 in this session has sent a sa to switch
	}

}

metadata meta_t meta;
/************METADATA ENDS*************/



/***************REGISTERS**************/
/****11 * 8192 byte = 88KB in total****/
register syn_proxy_status {
	width : 1;
	instance_count : 0;
}
register sa_seq_num_pool {
	width : 32;
	instance_count : 255;	//8 bit field
}
counter syn_counter {
	type : packets;
	static : confirm_connection_table;
	min_width : 32;
	instance_count : 1;
}
counter valid_ack_counter {
	type : packets;
	static : valid_connection_table;
	min_width : 32;
	instance_count : 1;
}
/*************REGISTERS ENDS***********/


action _no_op(){
	no_op();
}

action _drop() {
	drop();
}

action _resubmit()
{// 04
	resubmit(resubmit_FL);
}


/*******for syn_meter_table******/
{
	meter syn_meter {
		type : packets;
		result : meta.syn_meter_result;
		direct : syn_meter_table;
	}
	action syn_meter_action() {
		// turn on the switch of syn proxy if syn is too much (fast)
		if(meta.syn_meter_result == METER_COLOR_RED) {
			// i guess red color means large number of syn packets
			register_write(syn_proxy_status, 0, PROXY_ON);
		}
		// read syn proxy status into metadata
		register_read(meta.syn_proxy_status, syn_proxy_status, 0);
	}
	table syn_meter_table {
		actions {
			syn_meter_action;
		}
	}
}
/******for valid_connection_table*******/
{
	action set_ignore_syn_proxy_action() {
		modify_field(meta.forward_strategy, FORWARD_NORMALLY);
	}
	table valid_connection_table {
		reads {
			ipv4.srcAddr : exact;
			ipv4.dstAddr : exact;
			ipv4.protocol : exact;
			tcp.srcPort : exact;
			tcp.dstPort : exact;
		}
		actions {
			_no_op;
			set_ignore_syn_proxy_action;
		}
	}
}
/*******for eight_bit_index_select_table******/
{
	action eight_bit_index_select(ip_mask, ip_e_pos, port_mask, port_e_pos) {
		// masks must be 4 bits in a row
		// e.g. 00111100 00000000 00000000 00000000 (0x3c000000)
		modify_field(meta.eight_bit_index, 
				(((ipv4.srcAddr & ip_mask) >> ip_e_pos) << 4) | ((tcp.srcPort & port_mask) >> port_e_pos));
	}
	table eight_bit_index_select_table {
		actions {
			eight_bit_index_select;
		}
	}
}
/*******for reply_sa_table******/
{
	action reply_sa() {
		modify_field(meta.forward_strategy, FORWARD_REPLY_SA);
		// select syn+ack packet seq#
		register_read(meta.sa_seq_num, sa_seq_num_pool, meta.eight_bit_index);
		// count: syn packet
		count(syn_counter, 0);
	}
	table reply_sa_table {
		actions {
			reply_sa;
		}
	}
}
/*******for confirm_connection_table******/
{
	action confirm_connection() {
		// select syn+ack packet seq#
		register_read(meta.sa_seq_num, sa_seq_num_pool, meta.eight_bit_index);
		if(tcp.ackNo == meta.sa_seq_num + 1) {
			// valid ack#
			modify_field(meta.forward_strategy, FORWARD_ESTABLISH_WITH_SERVER);
			// count: valid ack
			count(valid_ack_counter, 0);
			// TODO: 记得把这个connection存储起来
		} else{
			modify_field(meta.forward_strategy, FORWARD_DROP_PKT);
		}
	}
	table confirm_connection_table {
		actions {
			confirm_connection;
		}
	}
}
/*******for check_syn_and_valid_ack_num_table******/
{
	action check_syn_and_valid_ack_num() {
		// check the difference between
		// the number of syn packets and the number of valid ack
		register_read(meta.syn_counter_val, syn_counter, 0);
		register_read(meta.valid_ack_counter_val, valid_ack_counter, 0);
		// if the difference of the two is less than 1/8 of the smaller one
		// we think that the number of syn pkts and valid ack pkts are roughly equal
		// shutdown syn proxy
		if(meta.syn_counter_val >= meta.valid_ack_counter_val){
			if((meta.syn_counter_val - meta.valid_ack_counter_val) > (meta.valid_ack_counter_val >> 3)){
				register_write(syn_proxy_status, 0, PROXY_OFF);
			}
		}else{
			if((meta.valid_ack_counter_val - meta.syn_counter_val) > (meta.syn_counter_val >> 3)){
				register_write(syn_proxy_status, 0, PROXY_OFF);
			}
		}
	}
	table check_syn_and_valid_ack_num_table {
		actions {
			check_syn_and_valid_ack_num;
		}
	}
}
/*******for no_syn_proxy_table******/
{
	action no_syn_proxy() {
		// forward every packets normally
		modify_field(meta.forward_strategy, FORWARD_NORMALLY);	
	}
	table no_syn_proxy_table {
		actions {
			no_syn_proxy;
		}
	}
}

// //**********for forward_table 
// action forward_normal()
// {//////05
	
// 	//There should be seq or ack transform 
// 	//change src mac and dst mac!!

// 	modify_field(standard_metadata.egress_spec, meta.out_port);

// }

// action sendback_sa()
// {
// 	modify_field(tcp.syn,1);
// 	modify_field(tcp.ack,1);
// 	modify_field(tcp.seqNo,0x0) ;
	
// 	modify_field(tcp.ackNo,meta.tcp_seqNo);
// 	add_to_field(tcp.ackNo,1);
// 	modify_field(ipv4.dstAddr, meta.ipv4_sa);
// 	modify_field(ipv4.srcAddr, meta.ipv4_da);
// 	modify_field(tcp.srcPort, meta.tcp_dp);
// 	modify_field(tcp.dstPort, meta.tcp_sp);
// 	modify_field(ethernet.dstAddr, meta.eth_sa);
// 	modify_field(ethernet.srcAddr, meta.eth_da);
		
// 	modify_field(standard_metadata.egress_spec, meta.in_port);
// }

// action sendback_session_construct()
// {
// 	modify_field(tcp.fin,1);
// 	modify_field(standard_metadata.egress_spec, meta.in_port);
// }


// action setack(port)
// {
// 	modify_field(tcp.syn,0);
// 	modify_field(tcp.ack,1);
// 	modify_field(tcp.seqNo, meta.dstip_pktcount);
// 	modify_field(standard_metadata.egress_spec, port);
// }

// action sendh2ack()
// {
// 	modify_field(tcp.syn,0);
// 	modify_field(tcp.ack,1);
// 	modify_field(tcp.ackNo, meta.tcp_seqNo);
// 	add_to_field(tcp.ackNo,1);

// 	modify_field(tcp.seqNo,meta.tcp_ackNo) ;
// 	modify_field(ipv4.dstAddr, meta.ipv4_sa);
// 	modify_field(ipv4.srcAddr, meta.ipv4_da);
// 	modify_field(tcp.srcPort, meta.tcp_dp);
// 	modify_field(tcp.dstPort, meta.tcp_sp);
// 	modify_field(ethernet.dstAddr, meta.eth_sa);
// 	modify_field(ethernet.srcAddr, meta.eth_da);
		
// 	modify_field(standard_metadata.egress_spec, meta.in_port);
// }

// action sendh2syn(port)
// {
// 	modify_field(tcp.syn,1);
// 	modify_field(tcp.ack,0);
// 	modify_field(tcp.seqNo, meta.tcp_seqNo);
// 	add_to_field(tcp.seqNo, -1);
// 	modify_field(tcp.ackNo,0);
	
// 	modify_field(standard_metadata.egress_spec,port);
// }

// //00 noreply  01 syn/ack back to h1  02 syn to h2  03 undifined  04 resubmit 05forward the packet 
// table forward_table{
// 	reads{
// 		meta.forward_strategy:exact;
// 	}

// 	actions{
// 		forward_normal;//forward_strategy:05
// 		_resubmit;//04
// 		sendh2ack;// 03
// 		sendh2syn;//02
// 		sendback_sa;//01
// 		sendback_session_construct;
// 		_drop;//0	
// 	}
// }

control ingress {
	// first count syn packets
	if(tcp.flags ^ TCP_FLAG_SYN == 0){
		// only has syn
		apply(syn_meter_table);
	}
	// check if this connection has been successfully established before
	// if so, ignore syn proxy mechanism
	apply(valid_connection_table);
	if(meta.forward_strategy != FORWARD_NORMALLY){
		// does not exist in valid_connection_table.
		// check if syn proxy is on
		if(meta.syn_proxy_status == PROXY_ON){
			// syn proxy on
			// no need for session check since we use stateless SYN-cookie method
			if(tcp.flags & (TCP_FLAG_ACK | TCP_FLAG_SYN) == (TCP_FLAG_ACK | TCP_FLAG_SYN)){
				// has syn + ack, may also have other flags
				
			} else if(tcp.flags & TCP_FLAG_SYN == TCP_FLAG_SYN){
				// has syn but no ack
				// send back syn+ack with special seq#
				apply(eight_bit_index_select_table);
				apply(reply_sa_table);
			} else if(tcp.flags & TCP_FLAG_ACK == TCP_FLAG_ACK){
				// has ack but no syn
				// make sure ack# is right
				apply(eight_bit_index_select_table);
				apply(confirm_connection_table);
			}
			// check the difference between
			// the number of syn packets and the number of valid ack
			apply(check_syn_and_valid_ack_num_table);
		}else {
			// syn proxy off
			// forward every packets normally
			apply(no_syn_proxy_table);
		}
	}
	if(meta.forward_strategy == FORWARD_NORMALLY){
		// TODO: next steps (detect packet size & num from each source ip)
	}
	apply(forward_table);	
}

control egress {
}

