#!/bin/bash

function handle_message()
{
  [ "$LOG_LEVEL" = "DEBUG" ] && echo "Resource monitor received SIGUSR1, exiting"
  exit 0
}

# trapping the SIGINT signal
trap handle_message SIGUSR1

OUTPUT_FILE=$1
LOG_LEVEL=$2

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

rm -f ${OUTPUT_FILE}

echo "Monitoring pmacct containers resource consumption -- outputting to file: $OUTPUT_FILE"

# No concurrency issues with test_name_logging fixture are expected, even though logging to the same file,
# because that fixture runs before any pmacct instances are deployed and after these are stopped
while true; do
  docker ps -af "name=(nfacctd|pmbmpd|pmbgpd|pmtelemetryd)-\d+" --format '{{.Names}}' | while read -r value; do
    if docker inspect $value >/dev/null 2>&1; then
      dte=$( date )
      msg=$( docker stats $value --no-stream --format '{{ json . }}' 2>/dev/null )
      if [ $? -eq 0 ]; then
        echo "$dte $value $msg" >> ${OUTPUT_FILE}
      fi
    fi
  done
  sleep 1
done
