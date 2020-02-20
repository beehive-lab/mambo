/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2013-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>

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

#include "dbm.h"
#include "scanner_public.h"
#ifdef __arm__
  #include "api/emit_thumb.h"
  #include "api/emit_arm.h"
  #include "pie/pie-arm-field-decoder.h"
  #include "pie/pie-arm-decoder.h"
  #include "pie/pie-thumb-field-decoder.h"
  #include "pie/pie-thumb-decoder.h"
#elif __aarch64__
  #include "api/emit_a64.h"
  #include "pie/pie-a64-field-decoder.h"
  #include "pie/pie-a64-decoder.h"
#endif
#include "api/helpers.h"
#include "scanner_common.h"
#include "api/hash_table.h"
