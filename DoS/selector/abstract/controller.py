from switch import Switch
import threading
import math
import time
import random
import operator
# import extractor

sending_packets = True

def write_to_file(datas, filename='./output.txt'):
    with open(filename, 'a+') as f:
        string = ''
        for data in datas:
            string = string + str(data) + ','
        string = string + '\n'
        f.writelines(string)
        f.close()

class Migration:
    src_switch = None
    dst_switch = None
    bucket_num = None

    def __init__(self, src_switch, dst_switch, bucket_num):
        self.src_switch = src_switch
        self.dst_switch = dst_switch
        self.bucket_num = bucket_num
        # print 'Migration Initiated! Bucket %d from switch %d to switch %d' % \
        #     (self.bucket_num, self.src_switch, self.dst_switch)

    def execute(self, switch_pool):
        switch_pool[self.dst_switch].add_bucket(self.bucket_num)
        switch_pool[self.src_switch].remove_bucket(self.bucket_num)

def generate_addr():
    # generate addresses
    addr = random.randint(0, math.pow(2, 32) - 1)
    return addr

def send_packets(switch_pool, packet_count, busy_switch=-1, another_switch_pool=None):
    for i in range(packet_count):
        addr = generate_addr()
        # generate flags
        # flags = random.randint(0, 10)
        for switch in switch_pool:
            switch.receive(addr)
        if another_switch_pool is not None:
            for switch in another_switch_pool:
                switch.receive(addr)
    if busy_switch != -1:
        for i in range(packet_count / 5):
            addr = generate_addr()
            switch_pool[busy_switch].receive(addr)
            if another_switch_pool is not None:
                another_switch_pool[busy_switch].receive(addr)

def read_and_redistribute_data(switch_pool, filename, redistribute=True, alpha=1.5):
    switch_count = len(switch_pool)
    flow_count_totals = []
    flow_counts = []
    for switch in switch_pool:
        flow_count_total, flow_count = switch.read_flow_count()
        flow_counts.append(flow_count)
        flow_count_totals.append(flow_count_total)
        print 'Switch %d has a total flow count of %d' % (switch.index, flow_count_total)
    write_to_file(flow_count_totals, filename)
    if redistribute:
        # loop until the distribution is relatively balanced
        migration_list = []
        while True:
            # find the busiest and the lowest-burdened switch
            min_switch = flow_count_totals.index(min(flow_count_totals))
            max_switch = flow_count_totals.index(max(flow_count_totals))
            if len(flow_counts[max_switch]) == 0:
                break
            if max_switch == min_switch:
                break
            if flow_count_totals[max_switch] - flow_count_totals[min_switch]    \
                <= flow_count_totals[min_switch] * 0.1:
                break
            # find the smallest bucket of the max_switch
            min_bucket = min(
                flow_counts[max_switch].iteritems(),
                key=operator.itemgetter(1)
            )
            # if the difference between busiest switch and min switch
            # is bigger than the smallest bucket of the busiest switch
            # migrate this bucket to the small one
            if flow_count_totals[max_switch] - \
                flow_count_totals[min_switch] >= alpha * min_bucket[1]:
                # add a migration job
                migration_list.append(Migration(max_switch, min_switch, min_bucket[0]))
                # change statistic values
                flow_count_totals[max_switch] = \
                    flow_count_totals[max_switch] - min_bucket[1]
                flow_count_totals[min_switch] = \
                    flow_count_totals[min_switch] + min_bucket[1]
                flow_counts[min_switch][min_bucket[0]] = min_bucket[1]
                flow_counts[max_switch].pop(min_bucket[0])
            else:
                break
        # finish all migrations
        for migration in migration_list:
            migration.execute(switch_pool)
        # output migration results
        print '%d entries migrated' % len(migration_list)
        for i in range(switch_count):
            print 'Switch %d has a total flow count of %d after migration' % (i, flow_count_totals[i])

    # clear all switches' statistic data
    for switch in switch_pool:
        switch.clear_flow_count()

def init_switches(switch_count, bucket_size):
    switch_pool = []
    # init switches
    for i in range(switch_count):
        switch_pool.append(Switch(i, bucket_size))
    return switch_pool

def distribute_buckets(switch_pool, bucket_size):
    switch_count = len(switch_pool)
    # distribute buckets
    for i in range(bucket_size):
        switch_index = i % switch_count
        switch_pool[switch_index].add_bucket(i)


def test():
    switch_count = 3
    bucket_size = 10000

    migrated_file='./output.txt'
    original_file='./output_original.txt'

    switch_pool = init_switches(switch_count, bucket_size)
    origin_switch_pool = init_switches(switch_count, bucket_size)

    distribute_buckets(switch_pool, bucket_size)
    distribute_buckets(origin_switch_pool, bucket_size)

    # send packets to switches

    term_count = 0
    round_count = 0
    busy_switch = -1
    packet_rate_base = 18000
    packet_rate_seiling = 55000
    packet_rate = packet_rate_seiling - packet_rate_seiling / 10
    term_count_static = 30 + random.randint(-10, 10)
    while True:
        send_packets(switch_pool, packet_rate, busy_switch=busy_switch, another_switch_pool=origin_switch_pool)
        read_and_redistribute_data(switch_pool, migrated_file)
        read_and_redistribute_data(origin_switch_pool, original_file, redistribute=False)
        # raw_input(  )
        term_count = term_count + 1
        packet_rate = packet_rate + \
            random.randint(-(packet_rate - packet_rate_base) / 20,
            (packet_rate_seiling - packet_rate) / 15)
        if term_count == term_count_static:
            term_count = 0
            round_count = round_count + 1
            busy_switch = (busy_switch + 1) % switch_count
            term_count_static = 30 + random.randint(-10, 10)
        if round_count == 4:
            busy_switch = -1
        elif round_count == 5:
            break




# try:
test()
    # extractor.draw(filename=migrated_file)
# except KeyboardInterrupt:
#     print " Shutting down."
#     sending_packets = False
# except Exception as e:
#     print e
#     print " Shutting down."
#     sending_packets = False
