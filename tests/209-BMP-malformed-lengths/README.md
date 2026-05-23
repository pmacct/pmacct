# 209-BMP-malformed-lengths

Shell integration checks for malformed BMP common header lengths.

The test covers two paths:

- TCP framing: a BMP peer advertises a total message length smaller than the BMP common header.
- PCAP savefile parsing: `bmp_process_packet()` receives a captured BMP payload whose advertised total length is smaller than the common header.

Run locally after building `pmbmpd`:

```sh
tests/209-BMP-malformed-lengths/run-malformed-bmp-lengths.sh
```

Set `PMBMPD=/path/to/pmbmpd` to test a non-default binary.
