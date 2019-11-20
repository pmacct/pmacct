CONFIG=avro_test.conf
INPUT=dump_huawei_output_one_sample
PMGRPCD_FOLDER=../../
PMGRPCD=$PMGRPCD_FOLDER/pmgrpcd.py

source ../functions.sh

#sudo /opt/daisy/pkg/kafka/confluent-4.1.1/bin/kafka-avro-console-consumer --bootstrap-server kafka.sbd.corproot.net:9093 --consumer.config /opt/daisy/pkg/kafka/confluent-4.1.1/properties/consumer.properties --property schema.registry.url=https://schema-registry.sbd.corproot.net --property print.key=false --property print.schema.ids=false --property schema.id.separator=: --topic daisy.test.device-avro-raw 
#process=$!
python3.7 $PMGRPCD -c $CONFIG  --file_importer_file $INPUT  
#sleep 1s
#sudo kill -9 $process
echo all good
