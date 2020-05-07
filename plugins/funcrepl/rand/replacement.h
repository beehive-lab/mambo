/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2020 Unai Martinez-Corral <unai.martinezcorral at ehu dot eus>
  Copyright 2020 Guillermo Callaghan <guillermocallaghan at hotmail dot com>
  Copyright 2020 The University of Manchester

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

#define FR_ORIGINAL "rand"
#define FR_REPLACEMENT rand_replacement

int32_t rand_replacement(void);
