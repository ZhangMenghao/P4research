# This python file aims to keep update of some of the flow table in the switch
# including syn cookie hash key (timely update)
# and check for the value of syn meter, syn counter, valid ack counter from time to time

import scapy.all
import subprocess
import os
import re
import time

syn_meter_name = 'syn_meter'
syn_counter_name = 'syn_counter'
vack_counter_name = 'valid_ack_counter'
proxy_status_table_name = 'check_proxy_status_table'
proxy_on_action_name = 'turn_on_proxy'
proxy_off_action_name = 'turn_off_proxy'
blacklist_register_name = 'blacklist_table'
whitelist_register_name = 'whitelist_table'
# evaluation purposes
proxy_table_entry_counter_name = 'proxy_table_valid_entry_counter'
proxy_status = -1

def send_to_CLI(cmd):
    this_dir = os.path.dirname(os.path.realpath(__file__))
    p = subprocess.Popen(os.path.join(this_dir, 'sswitch_CLI.sh'), stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    output = p.communicate(input=cmd)[0]
    # print output
    return output

def cli_register_read(register_name, index):
    return send_to_CLI('register_read ' + register_name + ' ' + str(index))

def cli_register_write(register_name, index, value):
    return send_to_CLI('register_write ' + register_name + ' ' + str(index) + ' ' + str(value))

def cli_meter_get_rates(meter_name, index):
    return send_to_CLI('meter_get_rates ' + meter_name + ' ' + str(index))

def cli_counter_read(counter_name, index):
    return send_to_CLI('counter_read ' + counter_name + ' ' + str(index))

def cli_table_reset_default(table_name):
    return send_to_CLI('table_reset_default ' + table_name)

def cli_table_set_default(table_name, default_action_name):
    return send_to_CLI('table_set_default ' + table_name + ' ' + default_action_name)

def cli_read_meter():
    global syn_meter_name
    # print 'Reading syn_meter data...'
    cli_meter_get_rates(syn_meter_name , 0)
    return 0

def read_counter(counter_name, index):
    raw_result = cli_counter_read(counter_name, index)
    pattern = re.compile(r'BmCounterValue\(packets=(\d+), bytes=(\d+)\)')
    match = pattern.search(raw_result)
    if(match):
        return (int(match.group(1)), int(match.group(2)))
    else:
        return None

def read_register(register_name, index):
    raw_result = cli_register_read(register_name, index)
    # print raw_result
    pattern = re.compile(register_name + r'\[\d+\]=\s*(\d+)')
    match = pattern.search(raw_result)
    if(match):
        return match.group(1)
    else:
        return None

def read_counters():
    global syn_counter_name
    global vack_counter_name
    # print 'Reading syn_counter and valid_ack_counter data...'

    counter_results = {}

    counter_results['syn'] = read_counter(syn_counter_name, 0)
    counter_results['vack'] = read_counter(vack_counter_name, 0)
    return counter_results

def turn_on_proxy():
    global proxy_status
    if proxy_status == 1:
        return
    print 'Turning on proxy...'
    cli_table_set_default(proxy_status_table_name, proxy_on_action_name)
    proxy_status = 1

def turn_off_proxy():
    global proxy_status
    if proxy_status == 0:
        return
    print 'Turning off proxy...'
    cli_table_set_default(proxy_status_table_name, proxy_off_action_name)
    proxy_status = 0

def check_syn_and_ack_number(listen_interval, last_counter_val, syn_packets_speed_threshold=1500, auto_on=True, auto_off=True):
    print 'last_counter_val:', last_counter_val
    # meter_result = cli_read_meter()
    counter_results = read_counters()
    print 'counter_results:', counter_results
    if last_counter_val[0] == -1 and last_counter_val[1] == -1:
        # do not calculate spped
        return [counter_results['syn'][0], counter_results['vack'][0]]

    print 'proxy_status:', proxy_status
    # syn speed
    syn_speed = float((counter_results['syn'][0] - last_counter_val[0]) / listen_interval)
    if syn_speed > syn_packets_speed_threshold and auto_on:
        print 'Syn Proxy On. \tSpeed of syn packets is %d.' % syn_speed
        turn_on_proxy()
    # number of syn & valid ack packets
    elif proxy_status != 0 and auto_off:
        syn_increase = counter_results['syn'][0] - last_counter_val[0]
        vack_increase = counter_results['vack'][0] - last_counter_val[1]
        print 'syn_increase:', syn_increase, 'vack_increase:', vack_increase
        if abs(syn_increase - vack_increase) < min(syn_increase, vack_increase) * 1 / 8.0:
            print 'Syn Proxy Off. \tDifferece between syn and valid ack packets during the last period is %d.' % abs(syn_increase - vack_increase)
            turn_off_proxy()

    return [counter_results['syn'][0], counter_results['vack'][0]]

def update_black_list(rows=4096):
    blacklist_result = [0] * rows
    for i in range(0, rows):
        blacklist_result[i] = read_register(blacklist_register_name, i)
        if blacklist_result[i] != None:
            if blacklist_result[i] >= 2: # 10 or 11
                cli_register_write(blacklist_register_name, i, 1)
            else:
                cli_register_write(blacklist_register_name, i, 0)

def update_white_list(rows=4096):
    whitelist_result = [0] * rows
    for i in range(0, rows):
        whitelist_result[i] = read_register(whitelist_register_name, i)
        if whitelist_result[i] != None:
            if whitelist_result[i] >= 2: # 10 or 11
                cli_register_write(whitelist_register_name, i, 1)
            else:
                cli_register_write(whitelist_register_name, i, 0)

# evaluation purposes
def check_proxy_table_entry_num():
    print 'proxy_table_entry_counter:', read_register(proxy_table_entry_counter_name, 0)

def main():
    global proxy_status
    listen_interval = 0.1
    last_counter_val = [-1, -1]
    while True:
        last_counter_val = check_syn_and_ack_number(listen_interval, last_counter_val, syn_packets_speed_threshold=4000, auto_off=True)
        # it takes about 2.5 sec to check 10 entries......
        # update_black_list(10)
        # update_white_list(10)
        check_proxy_table_entry_num()
        print '\n'
        time.sleep(listen_interval)


if __name__ == '__main__':
    main()

