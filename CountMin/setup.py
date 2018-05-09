import os
from shutil import copyfile

unit_duration = 20 # log_2 of unit duration (so 2**unit_duration)
total_time_bits = 48
log_units = 3 # log_2 of number of units
units = 2**log_units
threshold = 8*1000.0 # in bytes

copyfile('simple_router.config.template', 'simple_router.config')

with open('simple_router.config', 'a') as fd:
    time_mask = (2**(unit_duration+log_units)-1) - (2**unit_duration -1)
    for unit in range(units):
        time_value = unit*2**unit_duration
        if unit < units/2:
            unit_threshold = int((unit+1) * threshold / units + threshold/2 )
        else:
            unit_threshold = int((unit+1) * threshold / units)
        fd.write('table_add hhd.threshold_table hhd.set_threshold %d&&&%d => %d 0\n' % (time_value, time_mask, unit_threshold))

