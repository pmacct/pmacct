### Major:
- test needs to be in tests folder as the framework expects it
- traffic-reproducer-00.yml: change port from 9992 to 9991, while pmacct is listening at 9991 (see in nfacctd-00.conf the configured port)
- nfacctd-00.conf: set socket address to :: (since the test uses IPv6 with 0.0.0.0 would not receive anything)

### Minor:
- I could greatly simplify 106_test.py and remove unnecessary files. The test you copied was a complex one with 2 runs and log checking which you don't need for a simple repro. For a simple repro+check json output this is enough:

```python
def main(consumers):
    th = KTestHelper(testParams, consumers)
    assert th.spawn_traffic_container('traffic-reproducer-106')

    th.set_ignored_fields(['timestamp_arrival', 'timestamp_min', 'timestamp_max', 'stamp_inserted', 'stamp_updated'])
    assert th.read_and_compare_messages('daisy.flow', 'flow-00')
```
- I also processed the pcap to adjust timestamps (were not consecutive wrt. pcap timestamp and would confuse traffic reproduces who relies on inter packet delays). Can be done with traffic reproducer (see examples [here](https://github.com/network-analytics/traffic-reproducer/tree/master/examples/pcap_processing))
- traffic-reproducer-00.yml: change use sync now, to make the test reproducible (not strictly required for this test but in general good practice given pmacct bucketing, otherwise you might get packets in 2 different packets resulting in different aggregation and thus different test result)

### Hints:
- Run with OVERWRITE env var the first time to populate the expected output files (e.g. output-flow-00.json in this case):
```bash
sudo env PATH="$PATH" OVERWRITE=true ./runtest.sh 106
```
