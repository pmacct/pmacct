#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include "pmacct.h"
#include "packet_processor.h"


packet_processor load_dynamic_lib(char* lib_path)
{

    packet_processor processor = {
        NULL,
        NULL,
        NULL,
        NULL
    };

    void* handle = dlopen(lib_path, RTLD_NOW);
    if (!handle) {
        Log(LOG_ERR, "ERROR ( %s ): [parsing lib %s] Error when dlopen-ing provided library : %s\n", config.name, lib_path, dlerror());
        exit_gracefully(1);
    }

    processor.bgp_parse_msg = dlsym(handle, "bgp_parse_msg");
    if (!processor.bgp_parse_msg) {
        Log(LOG_ERR, "ERROR ( %s ): [parsing lib %s] bgp_parse_msg not found in dynamic parsing library.\n", config.name, lib_path);
        exit_gracefully(1);
    }
    
    processor.bmp_process_packet = dlsym(handle, "bmp_process_packet");
    if (!processor.bmp_process_packet) {
        Log(LOG_ERR, "ERROR ( %s ): [parsing lib %s] bgp_process_packet not found in dynamic parsing library.\n", config.name, lib_path);
        exit_gracefully(1);
    }

    processor.bmp_peer_init = dlsym(handle, "bmp_peer_init");
    if (!processor.bmp_peer_init) {
        Log(LOG_ERR, "ERROR ( %s ): [parsing lib %s] bgp_peer_init not found in dynamic parsing library.\n", config.name, lib_path);
        exit_gracefully(1);
    }

    processor.bmp_peer_close = dlsym(handle, "bmp_peer_close");
    if (!processor.bmp_peer_close) {
        Log(LOG_ERR, "ERROR ( %s ): [parsing lib %s] bgp_peer_close not found in dynamic parsing library.\n", config.name, lib_path);
        exit_gracefully(1);
    }

    return processor;
}