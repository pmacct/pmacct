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

#define __PLUGIN_CMN_CUSTOM_C

/* Includes */
#include "pmacct.h"
#include "plugin_cmn_custom.h"

/* Functions */
void custom_output_setup(char *custom_lib, char *custom_cfg_file, struct pm_custom_output *custom_output)
{
  const char *error;

  Log(LOG_INFO, "INFO ( %s/%s ): Loading custom output from: %s\n", config.name, config.type, custom_lib);

  custom_output->lib_handle = dlopen(custom_lib, RTLD_LAZY);
  if (!custom_output->lib_handle) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Could not load custom output library %s: %s\n", config.name, config.type, custom_lib, dlerror());
    exit_gracefully(1);
  }

  custom_output->plugin_init = dlsym(custom_output->lib_handle, "plugin_init");
  if ((error = dlerror()) != NULL)  {
    Log(LOG_ERR, "ERROR ( %s/%s ): %s from %s\n", config.name, config.type, error, custom_lib);
    exit_gracefully(1);
  }

  custom_output->plugin_destroy = dlsym(custom_output->lib_handle, "plugin_destroy");
  if ((error = dlerror()) != NULL)  {
    Log(LOG_ERR, "ERROR ( %s/%s ): %s from %s\n", config.name, config.type, error, custom_lib);
    exit_gracefully(1);
  }

  custom_output->print = dlsym(custom_output->lib_handle, "print");
  if ((error = dlerror()) != NULL)  {
    Log(LOG_ERR, "ERROR ( %s/%s ): %s from %s\n", config.name, config.type, error, custom_lib);
    exit_gracefully(1);
  }

  custom_output->open_file = dlsym(custom_output->lib_handle, "open_file");
  if ((error = dlerror()) != NULL)  {
    Log(LOG_ERR, "ERROR ( %s/%s ): %s from %s\n", config.name, config.type, error, custom_lib);
    exit_gracefully(1);
  }

  custom_output->close_file = dlsym(custom_output->lib_handle, "close_file");
  if ((error = dlerror()) != NULL)  {
    Log(LOG_ERR, "ERROR ( %s/%s ): %s from %s\n", config.name, config.type, error, custom_lib);
    exit_gracefully(1);
  }

  custom_output->flush_file = dlsym(custom_output->lib_handle, "flush_file");
  if ((error = dlerror()) != NULL)  {
    Log(LOG_ERR, "ERROR ( %s/%s ): %s from %s\n", config.name, config.type, error, custom_lib);
    exit_gracefully(1);
  }

  custom_output->get_error_text = dlsym(custom_output->lib_handle, "get_error_text");
  if ((error = dlerror()) != NULL)  {
    Log(LOG_ERR, "ERROR ( %s/%s ): %s from %s\n", config.name, config.type, error, custom_lib);
    exit_gracefully(1);
  }

  if (0 != custom_output->plugin_init(custom_cfg_file)) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Initialisation of custom output failed: %s\n", config.name, config.type, custom_output->get_error_text());
    exit_gracefully(1);
  }
}
