#include <stdio.h>
#include <string.h>

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
#define check_str(str, fb) (((str != NULL) && (strlen(str) > 0)) ? str : fb)
  printf("\nPlugins:\n\n");
  mambo_plugin *plugins = global_data.plugins;
  for (int k = 0; k < global_data.free_plugin; k++) {
    mambo_plugin_info *i = plugins[k].info;
    char str[256];
    (i != NULL) ?
      sprintf(str, "%s (%s): %s",
        check_str(i->name, "<no name>"),
        check_str(i->version, "untracked"),
        check_str(i->description, "<no description>")
      )
    : sprintf(str, "%s", "no plugin info available");
    printf("  [%i] %p %s\n", k, plugins[k].cbs, str);
  }

  watched_functions_t *wf = &global_data.watched_functions;

  if (wf->func_count) {
    printf("\nwatched func:\n\n");
    for (int i = 0; i < wf->func_count; i++) {
      watched_func_t *f = &wf->funcs[i];
      printf("  [%i] %s %s\n", f->plugin_id, f->name, "(<args>) -> <hook>");
    }
  }
  if (wf->funcp_count) {
    printf("\nwatched funcp:\n\n");
    for (int i = 0; i < wf->funcp_count; i++) {
      watched_funcp_t *fp = &wf->funcps[i];
      printf("  %p %s [%i]\n", fp->addr, fp->func->name, fp->func->plugin_id);
    }
  }
#endif
  printf("\n");
  return;
}

