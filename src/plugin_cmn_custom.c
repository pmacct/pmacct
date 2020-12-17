/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
*/

/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* Includes */
#include "pmacct.h"
#include "plugin_cmn_custom.h"

/* global variables */
struct pm_custom_output custom_print_plugin;

/* Functions */
void custom_output_setup(char *custom_lib, char *custom_cfg_file, struct pm_custom_output *custom_output)
{
#ifdef WITH_DLOPEN
  const char *error;

  Log(LOG_INFO, "INFO ( %s/%s ): Loading custom output from: %s\n", config.name, config.type, custom_lib);

  custom_output->lib_handle = dlopen(custom_lib, RTLD_LAZY);
  if (!custom_output->lib_handle) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Could not load custom output library %s: %s\n", config.name, config.type, custom_lib, dlerror());
    exit_gracefully(1);
  }

  /* ie. to init internal structures */
  custom_output->plugin_init = dlsym(custom_output->lib_handle, "plugin_init");
  if ((error = dlerror()) != NULL)  {
    Log(LOG_ERR, "ERROR ( %s/%s ): %s from %s\n", config.name, config.type, error, custom_lib);
    exit_gracefully(1);
  }

  /* ie. to destroy internal structures */
  custom_output->plugin_destroy = dlsym(custom_output->lib_handle, "plugin_destroy");
  if ((error = dlerror()) != NULL)  {
    Log(LOG_ERR, "ERROR ( %s/%s ): %s from %s\n", config.name, config.type, error, custom_lib);
    exit_gracefully(1);
  }

  /* ie. at purge time, given input data, to compose an object to flush */
  custom_output->print = dlsym(custom_output->lib_handle, "print");
  if ((error = dlerror()) != NULL)  {
    Log(LOG_ERR, "ERROR ( %s/%s ): %s from %s\n", config.name, config.type, error, custom_lib);
    exit_gracefully(1);
  }

  /* ie. at purge time initialize output backend (ie. open file, connect to broker) and
     optionally perform other start actions (ie. write start marker) */
  custom_output->output_init = dlsym(custom_output->lib_handle, "output_init");
  if ((error = dlerror()) != NULL)  {
    Log(LOG_ERR, "ERROR ( %s/%s ): %s from %s\n", config.name, config.type, error, custom_lib);
    exit_gracefully(1);
  }

  /* ie. at purge time close output backend (ie. close file, disconnect from broker) and
     optionally perform other start actions (ie. write end marker) */
  custom_output->output_close = dlsym(custom_output->lib_handle, "output_close");
  if ((error = dlerror()) != NULL)  {
    Log(LOG_ERR, "ERROR ( %s/%s ): %s from %s\n", config.name, config.type, error, custom_lib);
    exit_gracefully(1);
  }

  /* ie. at purge time write data to the backend and optionally perform other actions
     (ie. flushing buffers, if buffered output) */
  custom_output->output_flush = dlsym(custom_output->lib_handle, "output_flush");
  if ((error = dlerror()) != NULL)  {
    Log(LOG_ERR, "ERROR ( %s/%s ): %s from %s\n", config.name, config.type, error, custom_lib);
    exit_gracefully(1);
  }

  /* ie. nicely return error messages back */
  custom_output->get_error_text = dlsym(custom_output->lib_handle, "get_error_text");
  if ((error = dlerror()) != NULL)  {
    Log(LOG_ERR, "ERROR ( %s/%s ): %s from %s\n", config.name, config.type, error, custom_lib);
    exit_gracefully(1);
  }

  if (0 != custom_output->plugin_init(custom_cfg_file)) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Initialisation of custom output failed: %s\n", config.name, config.type, custom_output->get_error_text());
    exit_gracefully(1);
  }
#endif
}
