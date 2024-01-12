#include <stdio.h>

int main(int argc, char* argv[]) {
  int base = 2;
  int result = 1;
  for(int i = 0; i < 16; i++) {
    result *= base; 
  }
  printf("2^16 = %d\n", result);
}
