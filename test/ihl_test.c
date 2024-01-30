/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2022 The University of Manchester

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include <stdlib.h>
#include <stdio.h>

#define NO_ITERATIONS 10000

int main () {
    for (int i = 0; i < NO_ITERATIONS; i++) {
        int p_random_no = rand();
        switch (p_random_no)
        {
        case 0:
            fprintf(stderr, "%s %d\n", "Equal to ", 0);
            break;
        case 1:
            fprintf(stderr, "%s %d\n", "Equal to ", 1);
            break;

        case 2:
            fprintf(stderr, "%s %d\n", "Equal to ", 2);
            break;

        case 3:
            fprintf(stderr, "%s %d\n", "Equal to ", 3);
            break;

        case 4:
            fprintf(stderr, "%s %d\n", "Equal to ", 4);
            break;

        default:
            fprintf(stderr, "%s\n", "No match!");
            break;
        
        }
    }
    return 0;
}