## Test Description(209-BMP-EVPN-rawmsg)

Test for validating BMP EVPN route parsing coverage (route types 1..5) using curated `raw_msg` hex fixtures derived from sanitized BMP msglog data.

This test is fixture-based and does not require traffic replay. It ensures that:
- EVPN route types 1, 2, 3, 4 and 5 are all represented
- each sample is EVPN (`afi=25`, `safi=70`)
- `raw_msg` fields are valid hex blobs (`0x...`)
- route-type specific parsed fields are present as expected

### Provided files:
```
- 209_test.py                   pytest file defining EVPN route-type assertions
- evpn-rawmsg-samples.json      curated sanitized EVPN raw_msg samples and parsed fields
```

### Notes

- Samples are anonymized (public IPs/ASNs replaced) and contain no reference to AS20940.
- The test focuses on parser-output invariants for each EVPN route type rather than end-to-end pcap replay.
