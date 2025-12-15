#!/bin/bash
for i in {1..20}
do
    ./tcp-client 1000000000 &
done
wait
