#ifndef DBM_VERSION
#ifdef VERSION
  #define DBM_VERSION VERSION
#else
  #define DBM_VERSION "untracked"
#endif
#endif

void author(void);
void version(bool full);
void usage(char *argv0);
