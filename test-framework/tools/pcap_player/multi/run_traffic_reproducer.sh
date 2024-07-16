#!/bin/bash
exec > /pcap/run_traffic_reproducer.log
exec 2>&1

echo "$( date ) Running traffic reproducer multi"

pids=()
pcap_folders=( $( ls -d /pcap/*/ ) )
echo "$( date ) ${#pcap_folders[@]} folders found: ${pcap_folders[@]}"

for value in ${pcap_folders[@]}; do
#  sleep 1
  echo "$( date ) Running ${value}traffic-reproducer.yml"
  python3 main.py -t ${value}traffic-reproducer.yml -v > ${value}traffic-reproducer.log 2>&1 &
  pid=$!
  echo "$( date ) Spawned PID $pid"
  pids+=(${pid})
done

echo "$( date ) All spawned PIDs: ${pids[@]}"

echo "$( date ) All processes spawned, now waiting"
for pid in "${pids[@]}"; do
    echo "$( date ) Waiting for PID $pid"
    wait $pid
done
echo "$( date ) All processes finished"
