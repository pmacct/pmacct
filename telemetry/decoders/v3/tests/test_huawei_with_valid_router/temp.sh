set -x
RAW_DATA=test_huawei_raw_dump
FILE_EXPORT_ONE=test_huawei_output_one
#if [ -f $RAW_DATA ]; then
#	echo here
#	ln_raw=`wc -l < $RAW_DATA`
#else
#	echo tehre
#	ln_raw=0
#fi
#echo $ln_raw
source functions.sh

ln_raw=$(get_lines $RAW_DATA)
echo $ln_raw

if [ "$ln_raw" -eq "0" ]; then
	echo "Failed, raw file has no files";
	exit 1;
fi

# new
CONFIG_SECOND=test_huawei_second.conf
FILE_EXPORT_TWO=test_huawei_output_two
RAW_DATA_TWO=test_huawei_raw_dump_two

ln_out=$(get_lines $FILE_EXPORT_ONE)

if [ "$ln_out" -eq "0" ]; then
	echo "Failed, raw file has no files";
	exit 1;
fi

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
