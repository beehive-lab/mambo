/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2016 Cosmin Gorgovan <cosmin at linux-geek dot org>

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

/*
  Test file for plugin instr replacement and plugins/soft_div. It should print:

  827 413 1655
  9478 7108 7108
  4 434 1304

*/

.syntax unified

.global main
.func main
.code 32
main:
  PUSH {R4, LR}

  MOVW R3, #1655
  MOV R4, #2
  SDIV R1, R3, R4

  MOV R4, #4
  UDIV R2, R3, R4

  CMP R4, #4
  UDIVNE R3, R3, R4

  ADR R0, _tf
  BL printf

  BL div_thumb

  POP {R4, PC}
.endfunc

.global div_thumb
.func div_thumb
.thumb_func
div_thumb:
  PUSH {R4, LR}
  
  ITTTT EQ
  NOP
  NOP
  NOP
  NOP

  MOVW R3, #28435
  MOV R4, #3
  SDIV R1, R3, R4
  CMP R4, #3
  ITTET EQ
  MOVEQ R4, #4
  UDIVEQ R2, R3, R4
  UDIVNE R3, R3, R4
  UDIVEQ R3, R3, R4
  LDR R0, =_tf
  BL printf

  MOVW R1, #11
  MOVW R2, #12
  MOVW R3, #1304
  MOVW R4, #3
  CMP R4, #3
  ITTEE EQ
  MOVEQ R1, #4
  UDIVEQ R2, R3, R4
  MOVNE R4, #5
  UDIVNE R3, R3, R4
  LDR R0, =_tf
  BL printf

  POP {R4, PC}
.endfunc

_tf: .string "%d %d %d\n"
