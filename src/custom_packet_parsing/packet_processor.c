#include "packet_processor.h"
#include "dynamic_loading.h"

packet_processor active_packet_processor = DEFAULT_PACKET_PROCESSOR;

enum dynlib_result load_parsing_lib(const char* lib_path) {
  packet_processor processor = {0};
  const enum dynlib_result result = dynlib_load_and_resolve((struct dynlib){
      .path = lib_path,
      .table = (dynlib_table){
        {"bgp_parse_msg", (void**) &processor.bgp_parse_msg},
        {"bmp_process_packet", (void**) &processor.bmp_process_packet},
        {"bmp_peer_init", (void**) &processor.bmp_peer_init},
        {"bmp_peer_close", (void**) &processor.bmp_peer_close},
        {NULL,NULL}
      },
    }
  );

  // On dynlib success, actually set active packet processor to the loaded library
  if (result == DL_Success) {
    active_packet_processor = processor;
  }

  return result;
}
