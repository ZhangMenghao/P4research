#!/bin/bash
# speed ranges from 1-20
while :
do
    speed=`expr $RANDOM % 19 + 1` 
    wget 11.0.0.10:8080 --output-document=/dev/null -q --limit-rate=${speed}k -o /dev/null
    counter=`expr $counter + 1`
    echo ${counter}
done    