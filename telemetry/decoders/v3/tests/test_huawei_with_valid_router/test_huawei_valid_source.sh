#/bin/bash
# This test requires a huawei router to be dialing in to port :1000 (or change configuraation in CONFIG_FIRST
# First, let a connection come. Wait for some time
CONFIG_FIRST=test_huawei_first.conf
CONFIG_SECOND=test_huawei_second.conf
RAW_DATA=test_huawei_raw_dump
FILE_EXPORT_ONE=test_huawei_output_one
RAW_DATA_TWO=test_huawei_raw_dump_two
FILE_EXPORT_TWO=test_huawei_output_two
PMGRPCD_FOLDER=../../
PMGRPCD=$PMGRPCD_FOLDER/pmgrpcd.py

source ../functions.sh

rm -f log* $RAW_DATA $FILE_EXPORT_ONE $RAW_DATA_TWO $FILE_EXPORT_TWO
echo Starting process
python3.7 $PMGRPCD -c $CONFIG_FIRST -r $RAW_DATA --file_exporter_file $FILE_EXPORT_ONE &
process=$!
echo Process is $process
sleep 60s
echo Killing process
# kill process
kill -INT $process
sleep 1s
kill -9 $process


# If raw or output do not have output, fail
ln_raw=$(get_lines $RAW_DATA)

if [ "$ln_raw" -eq "0" ]; then
	echo "Failed, raw file has no files";
	exit 1;
fi
echo Raw created with $ln_raw lines

ln_out=$(get_lines $FILE_EXPORT_ONE)

if [ "$ln_out" -eq "0" ]; then
	echo "Failed, output file has no files";
	exit 1;
fi
echo output created with $ln_out lines

# Start new process with raw as input
# start server
python3.7 $PMGRPCD -c $CONFIG_SECOND -r $RAW_DATA_TWO --file_exporter_file $FILE_EXPORT_TWO &
process2=$!
echo Collector process $process2
sleep 1s
python3.7 $PMGRPCD_FOLDER/utils/huawei_generate_data.py -f $RAW_DATA &
process=$!
echo Generator process $process
sleep 10s
echo Killing process
# kill process
kill -INT $process2
sleep 1s
kill -9 $process
kill -9 $process2


set +x
# Check diffs
DIFF=$(diff $RAW_DATA $RAW_DATA_TWO) 
if [ "$DIFF" != "" ] 
then
	echo "Raws do not match"
	exit -2
fi

COMMAND_CLEAR="head -1 | sed 's/\"collection_timestamp\":[0-9]*,//g' | sed 's/\"grpcPeer\":\"[0-9\\.]*\",//g'"
clear_one="cat $FILE_EXPORT_ONE | $COMMAND_CLEAR"
clear_two="cat $FILE_EXPORT_TWO | $COMMAND_CLEAR"
DIFF=$(diff <(eval "$clear_one") <(eval "$clear_two"))
echo $DIFF
if [ "$DIFF" != "" ] 
then
	echo "Outputs do not match"
	exit -2
fi

# New output should be equal as first. If not fail.
echo all good
