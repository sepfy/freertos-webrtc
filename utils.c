#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "utils.h"

void utils_random_string(char *s, const int len) {

  int i;

  static const char alphanum[] =
   "0123456789"
   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
   "abcdefghijklmnopqrstuvwxyz";

  srand(time(NULL));

  for (i = 0; i < len; ++i) {
    s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
  }

  s[len] = '\0';
}
