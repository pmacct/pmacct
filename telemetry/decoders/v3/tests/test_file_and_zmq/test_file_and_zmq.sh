FILES="dump_huawei_output
"
rm -f log* 
CONFIG=file_test_output.conf
OUTPUT=file_test_output
ZMQ_OUTPUT=zmq_output
PMGRPCD_FOLDER=../../
PMGRPCD=$PMGRPCD_FOLDER/pmgrpcd.py

source ../functions.sh
for f in $FILES
do
	echo "Processing $f file..."
	ln=$(get_lines $f)
	if [ "$ln" -eq "0" ]; then
		echo "File $f does not exist or does not have lines";
		exit 1;
	fi
	
	rm -f $OUTPUT $ZMQ_OUTPUT
	python3.7 $PMGRPCD_FOLDER/utils/zmq_puller.py > $ZMQ_OUTPUT &
	process_zmq=$!
	sleep 2s
	echo zmq Process is $process_zmq
	python3.7 $PMGRPCD -c $CONFIG --file_exporter_file $OUTPUT --file_importer_file $f &
	process=$!
	echo Process is $process
	sleep 20s
	echo Killing process
	# kill process
	kill -9 $process
	kill -9 $process_zmq

	# we could try the filtering of the test_huawei, but it is a bit too complex. We'll just make sure the number of lines iss equal.
	if [ "$(wc -l < $f)" -ne "$(wc -l < $OUTPUT)" ]; then 
		echo Number of lines do not match
		exit 1
	fi

	# zmq and the file is a bit different, so we just complain if we dont have 95% (we assume the dumps are long)
	ln_file=`wc -l < $f`
	zmq_lines=`wc -l < $ZMQ_OUTPUT`
	echo $ln_file
	echo $zmq_lines
	percetage=`echo  $(( $zmq_lines*100/$ln_file ))`
	echo $percetage
	if [ $percetage -lt 95 ]; then
		echo percetage of zmq lines is too low. Maybe file should be longer?
		exit 1
	fi

done
echo all good
