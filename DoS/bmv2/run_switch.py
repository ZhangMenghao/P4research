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
proxy_status = -1

def send_to_CLI(cmd):
    this_dir = os.path.dirname(os.path.realpath(__file__))
    p = subprocess.Popen(os.path.join(this_dir, 'sswitch_CLI.sh'), stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    output = p.communicate(input=cmd)[0]
    # print output
    return output

def register_read(register_name, index):
    return send_to_CLI('register_read ' + register_name + ' ' + str(index))

def register_write(register_name, index, value):
    return send_to_CLI('register_write ' + register_name + ' ' + str(index) + ' ' + str(value))

def meter_get_rates(meter_name, index):
    return send_to_CLI('meter_get_rates ' + meter_name + ' ' + str(index))

def counter_read(counter_name, index):
    return send_to_CLI('counter_read ' + counter_name + ' ' + str(index))

def table_reset_default(table_name):
    return send_to_CLI('table_reset_default ' + table_name)
blacklist_register_name
def table_set_default(table_name, default_action_name):
    return send_to_CLI('table_set_default ' + table_name + ' ' + default_action_name)

def read_meter():
    global syn_meter_name
    # print 'Reading syn_meter data...'
    meter_get_rates(syn_meter_name , 0)
    return 0

def read_counters():
    global syn_counter_name
    global vack_counter_name
    # print 'Reading syn_counter and valid_ack_counter data...'

    counter_results = {}

    syn_counter_result = counter_read(syn_counter_name, 0)
    vack_counter_result = counter_read(vack_counter_name, 0)
    pattern = re.compile(r'BmCounterValue\(packets=(\d+), bytes=(\d+)\)')
    syn_match = pattern.search(syn_counter_result)
    if(syn_match):
        counter_results['syn'] = (int(syn_match.group(1)), int(syn_match.group(2)))
    vack_match = pattern.search(vack_counter_result)
    if(vack_match):
        counter_results['vack'] = (int(vack_match.group(1)), int(vack_match.group(2)))
    return counter_results

def turn_on_proxy():
    global proxy_status
    if proxy_status == 1:
        return
    print 'Turning on proxy...'
    print table_reset_default(proxy_status_table_name)
    print table_set_default(proxy_status_table_name, proxy_on_action_name)
    proxy_status = 1

def turn_off_proxy():
    global proxy_status
    if proxy_status == 0:
        return
    print 'Turning off proxy...'
    print table_reset_default(proxy_status_table_name)
    print table_set_default(proxy_status_table_name, proxy_off_action_name)
    proxy_status = 0
    
def check_syn_and_ack_number(listen_interval, last_counter_val, syn_packets_speed_threshold=100):
    print 'last_counter_val:', last_counter_val
    # meter_result = read_meter()
    counter_results = read_counters()
    print 'counter_results:', counter_results
    if last_counter_val[0] == -1 and last_counter_val[1] == -1:
        # do not calculate spped
        return [counter_results['syn'][0], counter_results['vack'][0]]
    # syn speed
    syn_speed = float((counter_results['syn'][0] - last_counter_val[0]) / listen_interval)
    if syn_speed > syn_packets_speed_threshold:
        print 'Syn Proxy On. \tSpeed of syn packets is %d.' % syn_speed
        turn_on_proxy()
    # number of syn & valid ack packets
    print 'proxy_status:', proxy_status
    if proxy_status == 1:
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
        register_result = register_read(blacklist_register_name, i)
        pattern = re.compile(blacklist_register_name + r'\[\d+\]=\s*(\d+)')
        match = pattern.search(register_result)
        if(match):
            blacklist_result[i] = match.group(1)
            if blacklist_result[i] >= 2: # 10 or 11
                register_write(blacklist_register_name, i, 1)
            else:
                register_write(blacklist_register_name, i, 0)

def update_white_list(rows=4096):
    whitelist_result = [0] * rows
    for i in range(0, rows):
        register_result = register_read(whitelist_register_name, i)
        pattern = re.compile(whitelist_register_name + r'\[\d+\]=\s*(\d+)')
        match = pattern.search(register_result)
        if(match):
            whitelist_result[i] = match.group(1)
            if whitelist_result[i] >= 2: # 10 or 11
                register_write(whitelist_register_name, i, 1)
            else:
                register_write(whitelist_register_name, i, 0)
def main():
    global proxy_status
    listen_interval = 0.1
    last_counter_val = [-1, -1]
    while True:
        last_counter_val = check_syn_and_ack_number(listen_interval, last_counter_val)
        # it takes about 2.5 sec to check 10 entries......
        # update_black_list(10)
        # update_white_list(10)
        print '\n'
        time.sleep(listen_interval)
    

if __name__ == '__main__':
    main()

