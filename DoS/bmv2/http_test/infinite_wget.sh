#!/bin/bash
# speed ranges from 1-13.5
while :
do
    speed=`expr $RANDOM % 125 + 10` 
    speed=`expr $speed / 10`
    wget 10.0.0.10:8080 --output-document=/dev/null -q --limit-rate=${speed}k
    counter=`expr $counter + 1`
    echo ${counter}
done    