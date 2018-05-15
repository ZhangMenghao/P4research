//********
//********HASHES********
//********

field_list tcp_five_tuple_list{
	ipv4.src_addr;
	ipv4.dst_addr;
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

field_list src_ip_list {
	ipv4.src_addr;
}
field_list_calculation src_ip_hash {
	input {
		src_ip_list;
	}
	algorithm : crc16;
	output_width : 16;
}
field_list dst_ip_list {
	ipv4.dst_addr;
}
field_list_calculation dst_ip_hash {
	input {
		dst_ip_list;
	}
	algorithm : crc16;
	output_width : 16;
}

field_list syn_cookie_key1_list{
	ipv4.src_addr;
	ipv4.dst_addr;
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
	ipv4.src_addr;
	ipv4.dst_addr;
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
	ipv4.dst_addr;
	ipv4.src_addr;
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
	ipv4.dst_addr;
	ipv4.src_addr;
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

field_list ip_hash_fields {
	ipv4.src_addr;
	// ipv4.dst_addr;
}
field_list_calculation heavy_hitter_hash0{
	input {
		ip_hash_fields;
	}
	algorithm:csum16;
	output_width:8;
}
field_list_calculation heavy_hitter_hash1{
	input{
		ip_hash_fields;
	}
	algorithm:crc16;
	output_width:8;
}
//********HASHES END********