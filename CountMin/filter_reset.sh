#!/bin/sh
CONTAINER_ID=`docker ps | tail -n 1 | cut -d ' ' -f 1`
ACTIVE_FILTER='A'

while true; do
    CUR_TIME=`echo "get_time_elapsed" | docker exec -i $CONTAINER_ID simple_switch_CLI | grep Runtime | head -n 1 | cut -d ':' -f 2`
    CUR_TIME=${CUR_TIME}000
    echo $CUR_TIME
    echo "register_write last_reset_time 0 $CUR_TIME" | docker exec -i $CONTAINER_ID simple_switch_CLI
    if [ $ACTIVE_FILTER == 'A' ] ; then
        echo "register_write is_a_active 0 1"
        echo "register_reset hashtable_b0" | docker exec -i $CONTAINER_ID simple_switch_CLI
        echo "register_reset hashtable_b1" | docker exec -i $CONTAINER_ID simple_switch_CLI
        echo "register_reset hashtable_b2" | docker exec -i $CONTAINER_ID simple_switch_CLI
        echo "register_reset hashtable_b3" | docker exec -i $CONTAINER_ID simple_switch_CLI
        ACTIVE_FILTER='B'
    else
        echo "register_write is_a_active 0 0"
        echo "register_reset hashtable_a0" | docker exec -i $CONTAINER_ID simple_switch_CLI
        echo "register_reset hashtable_a1" | docker exec -i $CONTAINER_ID simple_switch_CLI
        echo "register_reset hashtable_a2" | docker exec -i $CONTAINER_ID simple_switch_CLI
        echo "register_reset hashtable_a3" | docker exec -i $CONTAINER_ID simple_switch_CLI
        ACTIVE_FILTER='A'
    fi
    sleep 4
done
