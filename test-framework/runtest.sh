#!/bin/bash
###################################################
# Automated Testing Framework for Network Analytics
# Pytest wrapper script for running test cases or
# groups thereof
# nikolaos.tsokas@swisscom.com 30/06/2023
###################################################


function handle_interrupt() {
  echo "Called handle_interrupt"
  tools/stop_all.sh
}

# trapping the SIGINT signal
trap handle_interrupt SIGINT

function print_help() {
  echo "Usage:"
  echo -e " ./runtest.sh  [--dry] \\
               [--loglevel=<log level>] \\
               [--mark=<expression>] \\
               [--key=<expression>] \\
               [<test-case number or wildcard>[:<scenario or wildcard>] ... ]"  
  echo
  echo "Arguments:"
  echo "    --dry           Dry-run (print pytest command only without executing)"
  echo "    --exitfirst     Exit immediately after the first failed test case"
  echo "    --loglevel      Log level: INFO(=default log level) or DEBUG"
  echo "    --mark          Select test cases with pytest marker specified in the *_test.py file"
  echo "    --key           Select test cases with provided keyword in the test name (folder name)"
  echo
  echo "Examples:"
  echo "    ./runtest.sh 202                                  # run test 202[all scenarios]"
  echo "    ./runtest.sh 502:*                                # run test 502[all scenarios]"
  echo "    ./runtest.sh 502:00                               # run test 502[default scenario]"
  echo "    ./runtest.sh 103:02                               # run test 103[scenario 2]"
  echo "    ./runtest.sh 103:01 103:02                        # run test 103[scenarios 1 and 2]"
  echo "    ./runtest.sh 101 102 201 301                      # run tests 101, 102, 201 and 301 [all scenarios]"
  echo "    ./runtest.sh 101 103:02 201 301                   # run tests 101, 201 and 301 [all scenarios] and test 103[scenario 02]"
  echo "    ./runtest.sh 1* --exitfirst                       # run all 1XX tests[all scenarios]; stop testing upon any failure"
  echo "    ./runtest.sh 1* --mark=ipfixv10                   # run all 1XX tests[all scenarios] with IPFIX v10 data"
  echo "    ./runtest.sh 4*:01                                # run all 4XX tests[scenarios 1]"                                      
  echo "    ./runtest.sh --loglevel=DEBUG 2*                  # run all 2XX tests[all scenarios] with log level DEBUG"
  echo "    ./runtest.sh --loglevel=DEBUG 103 202             # run tests 103 and 202 [all scenarios] with log level DEBUG"
  echo "    ./runtest.sh *                                    # run all test cases[all scenarios]"
  echo "    ./runtest.sh * --mark=ipfix                       # run all test cases[all scenarios] with IPFIX/NFv9 data"
  echo "    ./runtest.sh * --key=ipv6                         # run all test cases[all scenarios] with keyword \"ipv6\" in the test-name"
  echo "    ./runtest.sh *:00                                 # run all test cases[default scenarios only]"
  echo "    ./runtest.sh --dry 4*                             # dry-run all 4XX tests[all scenarios]"
  echo "    ./runtest.sh --dry 401:01                         # dry-run test 401[scenario 1]"
  echo "    ./runtest.sh --dry * --key=cisco                  # dry-run all tests [all scenarios] with keyword \"cisco\" in the test-name"
  echo
  echo "This script needs to be run from the top level directory of the testing framework!"
}

function start_monitor() {
  tools/monitor.sh results/monitor.log $LOG_LEVEL &
  MONITOR_PID=$!
  [ "$LOG_LEVEL" = "DEBUG" ] && echo "Started pmacct monitor with pid $MONITOR_PID dumping to file results/monitor.log"
}

function stop_monitor() {
  kill -SIGUSR1 $MONITOR_PID
  [ "$LOG_LEVEL" = "DEBUG" ] && echo "Stopping pmacct monitor with pid $MONITOR_PID... "
  wait $MONITOR_PID
  [ "$LOG_LEVEL" = "DEBUG" ] && echo "Pmacct monitor stopped"
}

function run_pytest() {
  cmd="python3 -m pytest${EXIT_ON_FAILURE}${MARKERS}${KEYS} ${test_files[@]} --runconfig=$RUNCONFIG -c=pytest.ini \
    --log-cli-level=$LOG_LEVEL --log-file=results/pytestlog.log --html=results/report.html"
  if [ "$DRY_RUN" = "TRUE" ]; then
    echo -e "\nCommand to execute:\n$cmd\n\npytest dry run (collection-only):"
    cmd="$cmd --collect-only"
  else
    start_monitor
  fi
  eval "$cmd"
  retCode=$?
  [ "$DRY_RUN" = "TRUE" ] || stop_monitor
  return $retCode
}

lsout="$( ls | tr '\n' ' ')"
if [[ "$lsout" != *"library"*"pytest.ini"*"settings.conf"*"tools"* ]]; then
  echo "Script not run from framework's root directory"
  print_help
  exit 1
fi

arg_was_asterisk=1; [[ "$@ " == *"$lsout"* ]] && arg_was_asterisk=0 # space after $@ needed!
DRY_RUN="FALSE"
source ./settings.conf # getting default LOG_LEVEL
MARKERS=
EXIT_ON_FAILURE=
KEYS=
TESTS=()
for arg in "$@"
  do
    case $arg in
      '--help'|'-h') print_help; exit 0;;
      '--dry') DRY_RUN="TRUE";;
      '--exitfirst'|'-x') EXIT_ON_FAILURE=" -x";;
      '--loglevel='*) LOG_LEVEL=${arg/--loglevel=/};;
      '--mark='*) MARKERS=" -m \"${arg/--mark=/}\"";;
      '--key='*) KEYS=" -k \"${arg/--key=/}\"";;
      *) if [[ "$arg_was_asterisk" != "0" ]] || [[ "$lsout" != *"$arg "* ]]; then TESTS+=(${arg}); fi;;
    esac
  done

[[ "$arg_was_asterisk" == "0" ]] && TESTS+=("*:*")

args="${TESTS[@]}"
RUNCONFIG="${args// /_}"

test_files=()
for arg in "${TESTS[@]}"; do # getting the test case part
  arg="${arg%%:*}*"
  test_files+=( "../tests/${arg/\*\*/*}" ) # remove double asterisk, just in case
done

count=${#TESTS[@]}
if [ $count -lt 1 ]; then
  echo "No tests found for arguments: $@"
  print_help
  exit 1
fi

rm -rf results/assets results/report.html results/pytestlog.log results/monitor.log
if [[ "$count" == "1" ]] && [[ "${TESTS[@]}" =~ ^[0-9]{3}:[0-9]{2}$ ]]; then # single-test run
  testandscenario="${TESTS[@]}"
  test="${testandscenario:0:3}"
  scenario="${testandscenario:4:2}"
  testdir=$( ls -d ../tests/*/ | grep "${test}-" | sed 's#/$##' )
  resultstestdir="${testdir/tests/results}"
  [[ "$scenario" != "00" ]] && resultstestdir="${resultstestdir}__scenario-$scenario"
  run_pytest
  retCode=$?
  cp -rf results/pytestlog.log results/report.html results/assets results/monitor.log ${resultstestdir}/ > /dev/null 2>&1
else # multi-test run
  run_pytest
  retCode=$?
fi
exit "$retCode"
