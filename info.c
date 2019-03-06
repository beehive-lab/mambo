#include <stdio.h>

#include "dbm.h"
#include "info.h"

#define xstr(s) str(s)
#define str(s) #s

void author() {
    printf("\
Written by Cosmin Gorgovan, with contributions from Guillermo Callaghan\n\
and others (github.com/beehive-lab/mambo/graphs/contributors).\n\
\n\
Licensed under the Apache License, Version 2.0. MAMBO is distributed on an\n\
\"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express\n\
or implied.\n\
");
}

void version(bool full) {
  printf("MAMBO: A Low-Overhead Dynamic Binary Modification Tool for ARM (%s)\n", DBM_VERSION);
  if (full) {
#if defined(__GNUC__)
    const char *compiler="GNU GCC";
    const char *compiler_version=xstr(__GNUC__)"."xstr(__GNUC_MINOR__)"."xstr(__GNUC_PATCHLEVEL__);
#else
    const char *compiler="Unknown";
    const char *compiler_version="";
#endif
    printf(" Compiled with %s %s\n", compiler, compiler_version);

    author();
  }
  printf("\n");
  return;
}

void usage(char *argv0) {
  version(false);
  printf("Usage: %s <elf_file> [<arguments>]\n", argv0);

#ifdef PLUGINS_NEW
  printf("\nPlugins:\n\n");
  mambo_plugin *plugins = global_data.plugins;
  for (int i = 0; i < global_data.free_plugin; i++) {
    printf("  [%i] %p\n", i, plugins[i].cbs);
  }

  watched_functions_t *wf = &global_data.watched_functions;

  if (wf->func_count) {
    printf("\nwatched func: %i\n\n", wf->func_count);
    for (int i = 0; i < wf->func_count; i++) {
      watched_func_t *func = &wf->funcs[i];
      printf("  %s [%i]\n", func->name, func->plugin_id);
    }
  }
  if (wf->funcp_count) {
    printf("\nwatched funcp: %i\n\n", wf->funcp_count);
    for (int i = 0; i < wf->funcp_count; i++) {
      watched_funcp_t *funcp = &wf->funcps[i];
      printf("  %p %s [%i]\n", funcp->addr, funcp->func->name, funcp->func->plugin_id);
    }
  }
#endif
  printf("\n");
  return;
}

