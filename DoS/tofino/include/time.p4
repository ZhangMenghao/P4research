#include "tofino/constants.p4"
register write_time_in {
    width: 64;
    instance_count: 2048;
}
register write_time_eg {
    width:64;
    instance_count: 2048;
}

register countt {
    width:64;
    instance_count: 4;
}
blackbox stateful_alu update_countt {
    reg: countt;
    update_lo_1_value: register_lo+1;
    output_value: alu_lo;
    output_dst: meta.countt;
}
action update_countt() {
    update_countt.execute_stateful_alu(1);
}
@pragma stage 0
table update_countt {
    actions {update_countt;}
}

blackbox stateful_alu write_time_in {
    reg: write_time_in;
    update_lo_1_value: meta.time32;
}
blackbox stateful_alu write_time_eg {
    reg: write_time_eg;
    update_lo_1_value: meta.time32;
}

action write_time_in() {
    write_time_in.execute_stateful_alu(meta.countt);
}
action write_time_eg() {
    write_time_eg.execute_stateful_alu(meta.countt);
}
action time32_in() {
    modify_field(meta.time32,ig_intr_md_from_parser_aux.ingress_global_tstamp);
}
action time32_eg() {
    modify_field(meta.time32,eg_intr_md_from_parser_aux.egress_global_tstamp);
}
@pragma stage 0
table time32_in {
    actions{ time32_in;}
    size: 1;
}
@pragma stage 0
table write_time_in {
    actions { write_time_in;}
    size: 1;
}
table time32_eg {
    actions {time32_eg;}
    size: 1;
}
table write_time_eg {
    actions { write_time_eg;}
    size: 1;
}

