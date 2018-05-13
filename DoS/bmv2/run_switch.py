# This python file aims to keep update of some of the flow table in the switch
# including syn cookie hash key (timely update)
# and check for the value of syn meter, syn counter, valid ack counter from time to time

from scapy.all import *
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
proxy_status = 1

def send_to_CLI(cmd):
    this_dir = os.path.dirname(os.path.realpath(__file__))
    p = subprocess.Popen(os.path.join(this_dir, 'sswitch_CLI.sh'), stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    output = p.communicate(input=cmd)[0]
    # print output
    return output

def read_meter():
    global syn_meter_name
    # print 'Reading syn_meter data...'
    meter_result = send_to_CLI('meter_get_rates ' + syn_meter_name + ' 0')
    return 0

def read_counters():
    global syn_counter_name
    global vack_counter_name
    # print 'Reading syn_counter and valid_ack_counter data...'

    counter_results = {}

    syn_counter_result = send_to_CLI('counter_read ' + syn_counter_name + ' 0')
    vack_counter_result = send_to_CLI('counter_read ' + vack_counter_name + ' 0')
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
    print send_to_CLI('table_reset_default ' + proxy_status_table_name)
    print send_to_CLI('table_set_default ' + proxy_status_table_name + ' ' + proxy_on_action_name)
    proxy_status = 1

def turn_off_proxy():
    global proxy_status
    print send_to_CLI('table_reset_default ' + proxy_status_table_name)
    print send_to_CLI('table_set_default ' + proxy_status_table_name + ' ' + proxy_off_action_name)
    proxy_status = 0
    

def main():
    global proxy_status
    listen_interval = 0.5
    syn_packets_speed_threshold = 100
    last_counter_val = [0, 0]
    while True:
        # meter_result = read_meter()
        counter_results = read_counters()
        print counter_results
        # syn speed
        syn_speed = float((counter_results['syn'][0] - last_counter_val[0]) / listen_interval)
        if syn_speed > syn_packets_speed_threshold:
            print 'Syn Proxy On. \tSpeed of syn packets is %d.' % syn_speed
            turn_on_proxy()
        # number of syn & valid ack packets
        print proxy_status
        if proxy_status == 1:
            syn_increase = counter_results['syn'][0] - last_counter_val[0]
            vack_increase = counter_results['vack'][0] - last_counter_val[1]
            print syn_increase, vack_increase
            if abs(syn_increase - vack_increase) < min(syn_increase, vack_increase) * 1 / 8.0:
                print 'Syn Proxy Off. \tDifferece between syn and valid ack packets during the last period is %d.' % abs(syn_increase - vack_increase)
                turn_off_proxy()

        last_counter_val[0] = counter_results['syn'][0]
        last_counter_val[1] = counter_results['vack'][0]
        print last_counter_val
        time.sleep(listen_interval)
    

if __name__ == '__main__':
    main()
