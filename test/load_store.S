/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2017 The University of Manchester

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

/* Reg0 - heap pointer
   Reg1 - stack pointer */
#ifdef __arm__
.syntax unified

.global test_thumb16
.func
.thumb_func
.type test_thumb16, %function

test_thumb16:
  PUSH {R4 - R12, LR}
  MOV R12, SP
  MOV SP, R1

  // LDR{ , B, H}, STR{ ,B, H}
  MOV  R2, #0
  LDR  R3, [R0, R2]
  LDRB R3, [R0, R2]
  LDRH R3, [R0, R2]
  STR  R3, [R0, R2]
  STRB R3, [R0, R2]
  STRH R3, [R0, R2]

  MOV  R7, #4
  LDR  R3, [R0, R7]
  LDRB R3, [R0, R7]
  LDRH R3, [R0, R7]
  STR  R3, [R0, R7]
  STRB R3, [R0, R7]
  STRH R3, [R0, R7]

  MOV  R4, #100
  LDR  R3, [R0, R4]
  LDRB R3, [R0, R4]
  LDRH R3, [R0, R4]
  STR  R3, [R0, R4]
  STRB R3, [R0, R4]
  STRH R3, [R0, R4]

  // LDRI, LDRBI, LDRHI
  LDR  R2, [R0, #0]
  LDRB R2, [R0, #0]
  LDRH R2, [R0, #0]
  STR  R2, [R0, #0]
  STRB R2, [R0, #0]
  STRH R2, [R0, #0]

  LDR  R4, [R0, #12]
  LDRB R4, [R0, #12]
  LDRH R4, [R0, #12]
  STR  R4, [R0, #12]
  STRB R4, [R0, #12]
  STRH R4, [R0, #12]

  LDR  R5, [R0, #0x7c]
  LDRB R5, [R0, #0x1f]
  LDRH R5, [R0, #0x3e]
  STR  R5, [R0, #0x7c]
  STRB R5, [R0, #0x1f]
  STRH R5, [R0, #0x3e]

  // LDRSB, LDRSH
  MOV R2, #0
  LDRSB R3, [R0, R2]
  LDRSH R4, [R0, R2]
  ADD R5, R0, #100
  MOV R6, #80
  LDRSB R2, [R5, R6]
  LDRSH R4, [R5, R6]

  // LDMFD, STMEA
  ADD R5, R0, #1000
  LDMFD R5, {r1}
  LDMFD R5, {r1-r7}
  ADD R5, R0, #1000
  LDMFD R5!, {r1}
  LDMFD R5!, {r1-r4, r6-r7}

  MOV R4, R0
  STMEA R4, {r3}
  STMEA R4!, {r3}
  STMEA R4, {r0-r7}
  STMEA R4!, {r0-r3, r5-r7}

  // PUSH, POP
  PUSH {r0}
  PUSH {r0, r4}
  PUSH {r0-r7, lr}
  POP  {r0-r7}
  ADD  SP, SP, #4
  POP  {r0, r4}
  POP  {r0}

  // SP-relative load and store
  SUB SP, SP, #10240
  LDR R2, [SP, #0]
  LDR R3, [SP, #40]
  LDR R4, [SP, #0x3FC]
  STR R2, [SP, #0]
  STR R3, [SP, #40]
  STR R4, [SP, #0x3FC]

  MOV SP, R12
  POP {R4 - R12, PC}
.endfunc
.ltorg

.global end_test_thumb16
end_test_thumb16:

.global test_thumb32
.func
.thumb_func
.type test_thumb32, %function

test_thumb32:
  PUSH {R4 - R12, LR}
  VPUSH {D16-D31}
  VPUSH {D0-D15}
  MOV R12, SP
  MOV SP, R1

  // LDR{ , B, H}, STR{ ,B, H}
  MOV R2, #0
  LDR.W  R3, [R0, R2]
  LDRB.W R3, [R0, R2]
  LDRH.W R3, [R0, R2]
  STR.W  R3, [R0, R2]
  STRB.W R3, [R0, R2]
  STRH.W R3, [R0, R2]

  MOV R9, R0
  MOV R2, #8
  LDR.W  R3, [R9, R2]
  LDRB.W R3, [R9, R2]
  LDRH.W R3, [R9, R2]
  STR.W  R3, [R9, R2]
  STRB.W R3, [R9, R2]
  STRH.W R3, [R9, R2]

  MOV R11, #16
  LDR.W  R3, [R9, R11]
  LDRB.W R3, [R9, R11]
  LDRH.W R3, [R9, R11]
  STR.W  R3, [R9, R11]
  STRB.W R3, [R9, R11]
  STRH.W R3, [R9, R11]

  // LDR{ , B, H}, STR{ ,B, H} with LSL
  MOV R2, #0
  LDR.W  R3, [R0, R2, LSL #2]
  LDRB.W R3, [R0, R2, LSL #2]
  LDRH.W R3, [R0, R2, LSL #2]
  STR.W  R3, [R0, R2, LSL #2]
  STRB.W R3, [R0, R2, LSL #2]
  STRH.W R3, [R0, R2, LSL #2]

  MOV R9, R0
  MOV R2, #8
  LDR.W  R3, [R9, R2, LSL #1]
  LDRB.W R3, [R9, R2, LSL #1]
  LDRH.W R3, [R9, R2, LSL #1]
  STR.W  R3, [R9, R2, LSL #1]
  STRB.W R3, [R9, R2, LSL #1]
  STRH.W R3, [R9, R2, LSL #1]

  MOV R11, #16
  LDR.W  R3, [R9, R11, LSL #3]
  LDRB.W R3, [R9, R11, LSL #3]
  LDRH.W R3, [R9, R11, LSL #3]
  STR.W  R3, [R9, R11, LSL #3]
  STRB.W R3, [R9, R11, LSL #3]
  STRH.W R3, [R9, R11, LSL #3]

  // LDRI{ , B, H}, STR{ , B, H}
  LDR.W  R3, [R0, #0]
  LDRB.W R3, [R0, #0]
  LDRH.W R3, [R0, #0]
  STR.W  R3, [R0, #0]
  STRB.W R3, [R0, #0]
  STRH.W R3, [R0, #0]

  MOV R14, R0
  LDR.W  R3, [R14, #12]
  LDRB.W R3, [R14, #12]
  LDRH.W R3, [R14, #12]
  STR.W  R3, [R14, #12]
  STRB.W R3, [R14, #12]
  STRH.W R3, [R14, #12]

  MOV R8, R0
  LDR.W  R3, [R8, #0xFFF]
  LDRB.W R3, [R8, #0xFFF]
  LDRH.W R3, [R8, #0xFFF]
  STR.W  R3, [R8, #0xFFF]
  STRB.W R3, [R8, #0xFFF]
  STRH.W R3, [R8, #0xFFF]

  // LDRI{ , B, H}, STR{ , B, H} with negative offset
  ADD R2, R0, #2000
  LDR  R8, [R2, #-1]
  LDRB R8, [R2, #-1]
  LDRH R8, [R2, #-1]
  STR  R8, [R2, #-1]
  STRB R8, [R2, #-1]
  STRH R8, [R2, #-1]

  MOV R9, R2
  LDR  R8, [R9, #-255]
  LDRB R8, [R9, #-255]
  LDRH R8, [R9, #-255]
  STR  R8, [R9, #-255]
  STRB R8, [R9, #-255]
  STRH R8, [R9, #-255]

  // LDRI{ , B, H}, STR{ , B, H} with pre-index
  MOV R2, R0
  LDR  R8, [R2, #1]!
  LDRB R8, [R2, #1]!
  LDRH R8, [R2, #1]!
  STR  R8, [R2, #1]!
  STRB R8, [R2, #1]!
  STRH R8, [R2, #1]!

  LDR  R8, [R2, #255]!
  LDRB R8, [R2, #255]!
  LDRH R8, [R2, #255]!
  STR  R8, [R2, #255]!
  STRB R8, [R2, #255]!
  STRH R8, [R2, #255]!

  LDR  R8, [R2, #-255]!
  LDRB R8, [R2, #-255]!
  LDRH R8, [R2, #-255]!
  STR  R8, [R2, #-255]!
  STRB R8, [R2, #-255]!
  STRH R8, [R2, #-255]!

  // LDRI{ , B, H}, STR{ , B, H} with post-index
  MOV R9, R0
  LDR  R4, [R9], #1
  LDRB R4, [R9], #1
  LDRH R4, [R9], #1
  STR  R4, [R9], #1
  STRB R4, [R9], #1
  STRH R4, [R9], #1

  LDR  R5, [R9], #255
  LDRB R5, [R9], #255
  LDRH R5, [R9], #255
  STR  R5, [R9], #255
  STRB R5, [R9], #255
  STRH R5, [R9], #255

  LDR  R6, [R9], #-255
  LDRB R6, [R9], #-255
  LDRH R6, [R9], #-255
  STR  R6, [R9], #-255
  STRB R6, [R9], #-255
  STRH R6, [R9], #-255

  // LDRD, STRD, offset
  ADD R4, R0, #0x800
  LDRD R2, R3, [R4]
  LDRD R2, R3, [R4, #0x3FC]
  LDRD R2, R3, [R4, #-0x3FC]
  STRD R2, R3, [R4]
  STRD R2, R3, [R4, #0x3FC]
  STRD R2, R3, [R4, #-0x3FC]

  // LDRD, STRD, pre-index
  LDRD R6, R7, [R4, #4]!
  LDRD R6, R7, [R4, #0x3FC]!
  LDRD R6, R7, [R4, #-0x3FC]!
  STRD R6, R7, [R4, #4]!
  STRD R6, R7, [R4, #0x3FC]!
  STRD R6, R7, [R4, #-0x3FC]!

  // LDRD, STRD, post-index
  MOV R5, R0
  LDRD R2, R3, [R5], #4
  LDRD R2, R3, [R5], #0x3FC
  LDRD R2, R3, [R5], #-0x3FC
  STRD R2, R3, [R5], #4
  STRD R2, R3, [R5], #0x3FC
  STRD R2, R3, [R5], #-0x3FC

  // {LDM,STM}{FD,EA}
  ADD R3, R0, #0x800
  STMFD.W R3, {R2}
  LDMFD.W R3, {R2}
  STMFD.W R3, {R2-R11, R14}
  LDMFD.W R3, {R2-R11, R14}
  STMFD.W SP!, {R0}
  LDMFD.W SP!, {R0}
  STMFD.W SP!, {R0-R11, R14}
  LDMFD.W SP!, {R0-R11, R14}

  ADD R5, R0, #0x800
  STMEA.W R5, {R1}
  LDMEA.W R5, {R1}
  STMEA.W R5, {R2-R11, R14}
  LDMEA.W R5, {R2-R11, R14}
  STMEA.W R5!, {R4}
  LDMEA.W R5!, {R4}
  STMEA.W R5!, {R2-R4, R6-R11, R14}
  LDMEA.W R5!, {R2-R4, R6-R11, R14}

  // {LDR,STR}{,B,H}T
  MOV R8, R0
  LDRBT R7, [R0]
  LDRBT R2, [R8, #255]
  STRBT R7, [R8]
  STRBT R7, [R0, #255]
  LDRHT R4, [R0]
  LDRHT R3, [R0, #255]
  STRHT R5, [R0]
  STRHT R9, [R8, #255]
  LDRT  R3, [R0]
  STRT  R3, [R0]
  LDRT  R4, [R8, #255]
  STRT  R4, [R8, #255]

  // LDRS{B,H}{,T}
  ADD R9, R0, #0x800
  LDRSB.W R3, [R0]
  LDRSB.W R3, [R9, #0x3FF]
  LDRSB.W R3, [R9, #-0xFF]
  LDRSB.W R3, [R9], #0xFF
  LDRSB.W R3, [R9, #0xFF]!
  LDRSBT R4,  [R9, #0xFF]
  LDRSH.W R3, [R0]
  LDRSH.W R3, [R9, #0x3FF]
  LDRSH.W R3, [R9, #-0xFF]
  LDRSH.W R3, [R9], #0xFF
  LDRSH.W R3, [R9, #0xFF]!
  LDRSHT  R5, [R9, #0xff]

  // VPUSH,VPOP
  VPUSH {D0}
  VPUSH {S0}
  VPOP  {S0}
  VPOP  {D0}
  VPUSH {S4-S8}
  VPOP  {S4-S8}
  VPUSH {D4-D15}
  VPOP  {D4-D15}
  VPUSH {S0-S31}
  VPOP  {S0-S31}
  VPUSH {D16-D31}
  VPOP  {D16-D31}

  // VSTM, VLDM
  MOV R2, R0
  VSTM R2, {S0}
  VLDM R2, {S0}
  VSTM R2, {D0-D15}
  VLDM R2, {D0-D15}
  VSTM R2!, {S0}
  VLDM R2!, {S0}
  VSTM R2!, {D16-D31}
  VLDM R2!, {D16-D31}

  // VLDR, VSTR
  ADD R3, R0, 0x800
  VSTR S0, [R3]
  VLDR S0, [R3]
  VSTR D0, [R3]
  VLDR D0, [R3]
  VSTR S16, [R3, #0x3FC]
  VLDR S16, [R3, #0x3FC]
  VSTR D17, [R3, #-0x3FC]
  VLDR D17, [R3, #-0x3FC]

  // load exclusive
  ADD R8, R0, #0x100
  LDREX R2, [R8]
  LDREX R3, [R0, 0x3FC]
  LDREXB R4, [R0]
  LDREXH R5, [R8]
  LDREXD R6, R7, [R0]
  CLREX

  // VLD1 / VST1
  ADD R2, R0, #0x8000
  MOV R3, #0x20
  MOV R4, #0x40
  VLD1.8 D0[2], [R2]
  VLD1.8 D0[1], [R2]!
  VLD1.8 D0[0], [R2], R3
  VLD1.16 D0[2], [R2]
  VLD1.16 D0[1], [R2]!
  VLD1.16 D0[0], [R2], R4
  VLD1.32 D0[0], [R2]
  VLD1.32 D0[1], [R2]!
  VLD1.32 D0[0], [R2], R3

  VLD1.8  {D2[]}, [R2]
  VLD1.8  {D2[]}, [R2]!
  VLD1.8  {D2[]}, [R2], R3
  VLD1.16 {D2[]}, [R2]
  VLD1.16 {D2[]}, [R2]!
  VLD1.16 {D2[]}, [R2], R4
  VLD1.32 {D2[]}, [R2]
  VLD1.32 {D2[]}, [R2]!
  VLD1.32 {D2[]}, [R2], R3

  VLD1.8  {D1}, [R2]
  VLD1.8  {D1-D2}, [R2]
  VLD1.8  {D1-D3}, [R2]
  VLD1.8  {D1-D4}, [R2]
  VLD1.8  {D1}, [R2]!
  VLD1.8  {D1-D2}, [R2]!
  VLD1.8  {D1-D3}, [R2]!
  VLD1.8  {D1-D4}, [R2]!
  VLD1.8  {D1}, [R2], R3
  VLD1.8  {D1-D2}, [R2], R3
  VLD1.8  {D1-D3}, [R2], R3
  VLD1.8  {D1-D4}, [R2], R3
  VLD1.16 {D1}, [R2]
  VLD1.16 {D1-D2}, [R2]
  VLD1.16 {D1-D3}, [R2]
  VLD1.16 {D1-D4}, [R2]
  VLD1.16 {D1}, [R2]!
  VLD1.16 {D1-D2}, [R2]!
  VLD1.16 {D1-D3}, [R2]!
  VLD1.16 {D1-D4}, [R2]!
  VLD1.16 {D1}, [R2], R4
  VLD1.16 {D1-D2}, [R2], R4
  VLD1.16 {D1-D3}, [R2], R4
  VLD1.16 {D1-D4}, [R2], R4
  VLD1.32 {D1}, [R2]
  VLD1.32 {D1-D2}, [R2]
  VLD1.32 {D1-D3}, [R2]
  VLD1.32 {D1-D4}, [R2]
  VLD1.32 {D1}, [R2]!
  VLD1.32 {D1-D2}, [R2]!
  VLD1.32 {D1-D3}, [R2]!
  VLD1.32 {D1-D4}, [R2]!
  VLD1.32 {D1}, [R2], R3
  VLD1.32 {D1-D2}, [R2], R3
  VLD1.32 {D1-D3}, [R2], R3
  VLD1.32 {D1-D4}, [R2], R3

  VST1.8 D0[2], [R2]
  VST1.8 D0[1], [R2]!
  VST1.8 D0[0], [R2], R3
  VST1.16 D0[2], [R2]
  VST1.16 D0[1], [R2]!
  VST1.16 D0[0], [R2], R4
  VST1.32 D0[0], [R2]
  VST1.32 D0[1], [R2]!
  VST1.32 D0[0], [R2], R3

  VST1.8  {D1}, [R2]
  VST1.8  {D1-D2}, [R2]
  VST1.8  {D1-D3}, [R2]
  VST1.8  {D1-D4}, [R2]
  VST1.8  {D1}, [R2]!
  VST1.8  {D1-D2}, [R2]!
  VST1.8  {D1-D3}, [R2]!
  VST1.8  {D1-D4}, [R2]!
  VST1.8  {D1}, [R2], R3
  VST1.8  {D1-D2}, [R2], R3
  VST1.8  {D1-D3}, [R2], R3
  VST1.8  {D1-D4}, [R2], R3
  VST1.16 {D1}, [R2]
  VST1.16 {D1-D2}, [R2]
  VST1.16 {D1-D3}, [R2]
  VST1.16 {D1-D4}, [R2]
  VST1.16 {D1}, [R2]!
  VST1.16 {D1-D2}, [R2]!
  VST1.16 {D1-D3}, [R2]!
  VST1.16 {D1-D4}, [R2]!
  VST1.16 {D1}, [R2], R4
  VST1.16 {D1-D2}, [R2], R4
  VST1.16 {D1-D3}, [R2], R4
  VST1.16 {D1-D4}, [R2], R4
  VST1.32 {D1}, [R2]
  VST1.32 {D1-D2}, [R2]
  VST1.32 {D1-D3}, [R2]
  VST1.32 {D1-D4}, [R2]
  VST1.32 {D1}, [R2]!
  VST1.32 {D1-D2}, [R2]!
  VST1.32 {D1-D3}, [R2]!
  VST1.32 {D1-D4}, [R2]!
  VST1.32 {D1}, [R2], R3
  VST1.32 {D1-D2}, [R2], R3
  VST1.32 {D1-D3}, [R2], R3
  VST1.32 {D1-D4}, [R2], R3

  // VLD2 / VST2
  VLD2.8  {D0[2], D1[2]}, [R2]
  VLD2.8  {D0[1], D1[1]}, [R2]!
  VLD2.8  {D0[0], D1[0]}, [R2], R3
  VLD2.16 {D0[2], D1[2]}, [R2]
  VLD2.16 {D0[1], D1[1]}, [R2]!
  VLD2.16 {D0[0], D1[0]}, [R2], R4
  VLD2.32 {D0[0], D1[0]}, [R2]
  VLD2.32 {D0[1], D1[1]}, [R2]!
  VLD2.32 {D0[0], D1[0]}, [R2], R3

  VLD2.8  {D2[], D3[]}, [R2]
  VLD2.8  {D2[], D3[]}, [R2]!
  VLD2.8  {D2[], D3[]}, [R2], R3
  VLD2.16 {D2[], D3[]}, [R2]
  VLD2.16 {D2[], D3[]}, [R2]!
  VLD2.16 {D2[], D3[]}, [R2], R4
  VLD2.32 {D2[], D3[]}, [R2]
  VLD2.32 {D2[], D3[]}, [R2]!
  VLD2.32 {D2[], D3[]}, [R2], R3

  VLD2.8  {D1-D2}, [R2]
  VLD2.8  {D1-D4}, [R2]
  VLD2.8  {D1-D2}, [R2]!
  VLD2.8  {D1-D4}, [R2]!
  VLD2.8  {D1-D2}, [R2], R3
  VLD2.8  {D1-D4}, [R2], R3
  VLD2.16 {D1-D2}, [R2]
  VLD2.16 {D1-D4}, [R2]
  VLD2.16 {D1-D2}, [R2]!
  VLD2.16 {D1-D4}, [R2]!
  VLD2.16 {D1-D2}, [R2], R4
  VLD2.16 {D1-D4}, [R2], R4
  VLD2.32 {D1-D2}, [R2]
  VLD2.32 {D1-D4}, [R2]
  VLD2.32 {D1-D2}, [R2]!
  VLD2.32 {D1-D4}, [R2]!
  VLD2.32 {D1-D2}, [R2], R3
  VLD2.32 {D1-D4}, [R2], R3

  VST2.8  {D0[2], D1[2]}, [R2]
  VST2.8  {D0[1], D1[1]}, [R2]!
  VST2.8  {D0[0], D1[0]}, [R2], R3
  VST2.16 {D0[2], D1[2]}, [R2]
  VST2.16 {D0[1], D1[1]}, [R2]!
  VST2.16 {D0[0], D1[0]}, [R2], R4
  VST2.32 {D0[0], D1[0]}, [R2]
  VST2.32 {D0[1], D1[1]}, [R2]!
  VST2.32 {D0[0], D1[0]}, [R2], R3

  VST2.8  {D1-D2}, [R2]
  VST2.8  {D1-D4}, [R2]
  VST2.8  {D1-D2}, [R2]!
  VST2.8  {D1-D4}, [R2]!
  VST2.8  {D1-D2}, [R2], R3
  VST2.8  {D1-D4}, [R2], R3
  VST2.16 {D1-D2}, [R2]
  VST2.16 {D1-D4}, [R2]
  VST2.16 {D1-D2}, [R2]!
  VST2.16 {D1-D4}, [R2]!
  VST2.16 {D1-D2}, [R2], R4
  VST2.16 {D1-D4}, [R2], R4
  VST2.32 {D1-D2}, [R2]
  VST2.32 {D1-D4}, [R2]
  VST2.32 {D1-D2}, [R2]!
  VST2.32 {D1-D4}, [R2]!
  VST2.32 {D1-D2}, [R2], R3
  VST2.32 {D1-D4}, [R2], R3

  // VLD3 / VST3
  VLD3.8  {D0[2], D1[2], D2[2]}, [R2]
  VLD3.8  {D0[1], D1[1], D2[1]}, [R2]!
  VLD3.8  {D0[0], D1[0], D2[0]}, [R2], R3
  VLD3.16 {D0[2], D1[2], D2[2]}, [R2]
  VLD3.16 {D0[1], D1[1], D2[1]}, [R2]!
  VLD3.16 {D0[0], D1[0], D2[0]}, [R2], R4
  VLD3.32 {D0[0], D1[0], D2[0]}, [R2]
  VLD3.32 {D0[1], D1[1], D2[1]}, [R2]!
  VLD3.32 {D0[0], D1[0], D2[0]}, [R2], R3

  VLD3.8  {D2[], D3[], D4[]}, [R2]
  VLD3.8  {D2[], D3[], D4[]}, [R2]!
  VLD3.8  {D2[], D3[], D4[]}, [R2], R3
  VLD3.16 {D2[], D3[], D4[]}, [R2]
  VLD3.16 {D2[], D3[], D4[]}, [R2]!
  VLD3.16 {D2[], D3[], D4[]}, [R2], R4
  VLD3.32 {D2[], D3[], D4[]}, [R2]
  VLD3.32 {D2[], D3[], D4[]}, [R2]!
  VLD3.32 {D2[], D3[], D4[]}, [R2], R3

  VLD3.8  {D1-D3}, [R2]
  VLD3.8  {D1-D3}, [R2]!
  VLD3.8  {D1-D3}, [R2], R3
  VLD3.16 {D1-D3}, [R2]
  VLD3.16 {D1-D3}, [R2]!
  VLD3.16 {D1-D3}, [R2], R4
  VLD3.32 {D1-D3}, [R2]
  VLD3.32 {D1-D3}, [R2]!
  VLD3.32 {D1-D3}, [R2], R3

  VST3.8  {D0[2], D1[2], D2[2]}, [R2]
  VST3.8  {D0[1], D1[1], D2[1]}, [R2]!
  VST3.8  {D0[0], D1[0], D2[0]}, [R2], R3
  VST3.16 {D0[2], D1[2], D2[2]}, [R2]
  VST3.16 {D0[1], D1[1], D2[1]}, [R2]!
  VST3.16 {D0[0], D1[0], D2[0]}, [R2], R4
  VST3.32 {D0[0], D1[0], D2[0]}, [R2]
  VST3.32 {D0[1], D1[1], D2[1]}, [R2]!
  VST3.32 {D0[0], D1[0], D2[0]}, [R2], R3

  VST3.8  {D1-D3}, [R2]
  VST3.8  {D1-D3}, [R2]!
  VST3.8  {D1-D3}, [R2], R3
  VST3.16 {D1-D3}, [R2]
  VST3.16 {D1-D3}, [R2]!
  VST3.16 {D1-D3}, [R2], R4
  VST3.32 {D1-D3}, [R2]
  VST3.32 {D1-D3}, [R2]!
  VST3.32 {D1-D3}, [R2], R3

  // VLD4 / VST4
  VLD4.8  {D0[2], D1[2], D2[2], D3[2]}, [R2]
  VLD4.8  {D0[1], D1[1], D2[1], D3[1]}, [R2]!
  VLD4.8  {D0[0], D1[0], D2[0], D3[0]}, [R2], R3
  VLD4.16 {D0[2], D1[2], D2[2], D3[2]}, [R2]
  VLD4.16 {D0[1], D1[1], D2[1], D3[1]}, [R2]!
  VLD4.16 {D0[0], D1[0], D2[0], D3[0]}, [R2], R4
  VLD4.32 {D0[0], D1[0], D2[0], D3[0]}, [R2]
  VLD4.32 {D0[1], D1[1], D2[1], D3[1]}, [R2]!
  VLD4.32 {D0[0], D1[0], D2[0], D3[0]}, [R2], R3

  VLD4.8  {D2[], D3[], D4[], D5[]}, [R2]
  VLD4.8  {D2[], D3[], D4[], D5[]}, [R2]!
  VLD4.8  {D2[], D3[], D4[], D5[]}, [R2], R3
  VLD4.16 {D2[], D3[], D4[], D5[]}, [R2]
  VLD4.16 {D2[], D3[], D4[], D5[]}, [R2]!
  VLD4.16 {D2[], D3[], D4[], D5[]}, [R2], R4
  VLD4.32 {D2[], D3[], D4[], D5[]}, [R2]
  VLD4.32 {D2[], D3[], D4[], D5[]}, [R2]!
  VLD4.32 {D2[], D3[], D4[], D5[]}, [R2], R3

  VLD4.8  {D1-D4}, [R2]
  VLD4.8  {D1-D4}, [R2]!
  VLD4.8  {D1-D4}, [R2], R3
  VLD4.16 {D1-D4}, [R2]
  VLD4.16 {D1-D4}, [R2]!
  VLD4.16 {D1-D4}, [R2], R4
  VLD4.32 {D1-D4}, [R2]
  VLD4.32 {D1-D4}, [R2]!
  VLD4.32 {D1-D4}, [R2], R3

  VST4.8  {D0[2], D1[2], D2[2], D3[2]}, [R2]
  VST4.8  {D0[1], D1[1], D2[1], D3[1]}, [R2]!
  VST4.8  {D0[0], D1[0], D2[0], D3[0]}, [R2], R3
  VST4.16 {D0[2], D1[2], D2[2], D3[2]}, [R2]
  VST4.16 {D0[1], D1[1], D2[1], D3[1]}, [R2]!
  VST4.16 {D0[0], D1[0], D2[0], D3[0]}, [R2], R4
  VST4.32 {D0[0], D1[0], D2[0], D3[0]}, [R2]
  VST4.32 {D0[1], D1[1], D2[1], D3[1]}, [R2]!
  VST4.32 {D0[0], D1[0], D2[0], D3[0]}, [R2], R3

  VST4.8  {D1-D4}, [R2]
  VST4.8  {D1-D4}, [R2]!
  VST4.8  {D1-D4}, [R2], R3
  VST4.16 {D1-D4}, [R2]
  VST4.16 {D1-D4}, [R2]!
  VST4.16 {D1-D4}, [R2], R4
  VST4.32 {D1-D4}, [R2]
  VST4.32 {D1-D4}, [R2]!
  VST4.32 {D1-D4}, [R2], R3

  // literal loads - these will not trap
  LDR.W  R2, litl
  LDRB.W R3, litl
  LDRH.W R4, litl
  LDRD.W R5, litl
  LDRSB.W R6, litl
  LDRSH.W R7, litl

  MOV SP, R12
  VPOP {D0-D15}
  VPOP {D16-D31}
  POP {R4 - R12, PC}
.endfunc
.ltorg

.align 3
litl: .quad 0

.global end_test_thumb32
end_test_thumb32:

.global test_a32
.func
.code 32
.type test_a32, %function
test_a32:
  PUSH {R4-R12, LR}
  MOV R12, SP
  MOV SP, R1

  // LDR{,B, H, SB, SH, T, BT, HT, SBT, SHT} (imm)
  ADD R5, R0, #0x1000
  LDR R2, [R5, #0]
  LDR R2, [R5, #12]
  LDR R8, [R5, #0xFFF]
  LDR R9, [R5, #-4]
  LDR R9, [R5, #-0xFFF]

  LDR R4, [R5], #4
  LDR R6, [R5], #0xFFF
  LDR R7, [R5], #-0xFFF
  LDR R8, [R5], #0

  LDR R2, [R5, #0]!
  LDR R3, [R5, #0xFFF]!
  LDR R4, [R5, #-0xFFF]!

  LDRB R2, [R5, #0]
  LDRB R2, [R5, #16]
  LDRB R8, [R5, #0xFFF]
  LDRB R9, [R5, #-7]
  LDRB R9, [R5, #-0xFFF]

  LDRB R4, [R5], #8
  LDRB R6, [R5], #0xFFF
  LDRB R7, [R5], #-0xFFF
  LDRB R8, [R5], #0

  LDRB R2, [R5, #0]!
  LDRB R3, [R5, #0xFFF]!
  LDRB R4, [R5, #-0xFFF]!

  LDRH R2, [R5, #0]
  LDRH R2, [R5, #20]
  LDRH R8, [R5, #0xFF]
  LDRH R9, [R5, #-40]
  LDRH R9, [R5, #-0xFF]

  LDRH R4, [R5], #20
  LDRH R6, [R5], #0xFF
  LDRH R7, [R5], #-0xFF
  LDRH R8, [R5], #0

  LDRH R2, [R5, #0]!
  LDRH R3, [R5, #0xFF]!
  LDRH R4, [R5, #-0xFF]!

  LDRSB R2, [R5, #0]
  LDRSB R2, [R5, #20]
  LDRSB R8, [R5, #0xFF]
  LDRSB R9, [R5, #-40]
  LDRSB R9, [R5, #-0xFF]

  LDRSB R4, [R5], #20
  LDRSB R6, [R5], #0xFF
  LDRSB R7, [R5], #-0xFF
  LDRSB R8, [R5], #0

  LDRSB R2, [R5, #0]!
  LDRSB R3, [R5, #0xFF]!
  LDRSB R4, [R5, #-0xFF]!

  LDRSH R2, [R5, #0]
  LDRSH R2, [R5, #20]
  LDRSH R8, [R5, #0xFF]
  LDRSH R9, [R5, #-40]
  LDRSH R9, [R5, #-0xFF]

  LDRSH R4, [R5], #20
  LDRSH R6, [R5], #0xFF
  LDRSH R7, [R5], #-0xFF
  LDRSH R8, [R5], #0

  LDRSH R2, [R5, #0]!
  LDRSH R6, [R5, #36]!
  LDRSH R3, [R5, #0xFF]!
  LDRSH R4, [R5, #-0xFF]!

  LDRT R4, [R5], #4
  LDRT R6, [R5], #0xFFF
  LDRT R7, [R5], #-0xFFF
  LDRT R8, [R5], #0

  LDRBT R4, [R5], #4
  LDRBT R6, [R5], #0xFFF
  LDRBT R7, [R5], #-0xFFF
  LDRBT R8, [R5], #0

  LDRHT R4, [R5], #4
  LDRHT R6, [R5], #0xFF
  LDRHT R7, [R5], #-0xFF
  LDRHT R8, [R5], #0

  LDRSBT R4, [R5], #4
  LDRSBT R6, [R5], #0xFF
  LDRSBT R7, [R5], #-0xFF
  LDRSBT R8, [R5], #0

  LDRSHT R4, [R5], #4
  LDRSHT R6, [R5], #0xFF
  LDRSHT R7, [R5], #-0xFF
  LDRSHT R8, [R5], #0

  // STR{,B ,H, T, BT, HT} (imm)
  ADD R10, R0, 0x2000
  STR R3, [R10, #0]
  STR R4, [R10, #12]
  STR R5, [R10, #-12]
  STR R5, [R10, #0xFFF]
  STR R4, [R10, #-0xFFF]

  STR R3, [R10], #0
  STR R3, [R10], #12
  STR R3, [R10], #-12
  STR R4, [R10], #0xFFF
  STR R4, [R10], #-0xFFF

  STR R3, [R10, #0]!
  STR R3, [R10, #12]!
  STR R3, [R10, #-12]!
  STR R4, [R10, #0xFFF]!
  STR R4, [R10, #-0xFFF]!

  STRB R3, [R10, #0]
  STRB R4, [R10, #24]
  STRB R5, [R10, #24]
  STRB R5, [R10, #0xFFF]
  STRB R4, [R10, #-0xFFF]

  STRB R3, [R10], #0
  STRB R3, [R10], #24
  STRB R3, [R10], #-24
  STRB R4, [R10], #0xFFF
  STRB R4, [R10], #-0xFFF

  STRB R3, [R10, #0]!
  STRB R3, [R10, #24]!
  STRB R3, [R10, #-24]!
  STRB R4, [R10, #0xFFF]!
  STRB R4, [R10, #-0xFFF]!

  STRH R3, [R10, #0]
  STRH R4, [R10, #24]
  STRH R5, [R10, #24]
  STRH R5, [R10, #0xFF]
  STRH R4, [R10, #-0xFF]

  STRH R3, [R10], #0
  STRH R3, [R10], #24
  STRH R3, [R10], #-24
  STRH R4, [R10], #0xFF
  STRH R4, [R10], #-0xFF

  STRH R3, [R10, #0]!
  STRH R3, [R10, #24]!
  STRH R3, [R10, #-24]!
  STRH R4, [R10, #0xFF]!
  STRH R4, [R10, #-0xFF]!

  STRT R3, [R10], #0
  STRT R3, [R10], #60
  STRT R3, [R10], #-60
  STRT R4, [R10], #0xFFF
  STRT R4, [R10], #-0xFFF

  STRBT R3, [R10], #0
  STRBT R3, [R10], #64
  STRBT R3, [R10], #-64
  STRBT R4, [R10], #0xFF
  STRBT R4, [R10], #-0xFF

  STRHT R3, [R10], #0
  STRHT R3, [R10], #68
  STRHT R3, [R10], #-68
  STRHT R4, [R10], #0xFF
  STRHT R4, [R10], #-0xFF

  // LDR{, B, H, SB, SH} (reg)
  MOV R3, #0
  MOV R4, #0x300
  ADD R5, R0, #0x3000
  LDR R2, [R5, R3]
  LDR R2, [R5, R4]
  LDR R2, [R5, R4, LSL #1]
  LDR R2, [R5, R4, LSR #1]
  LDR R2, [R5, R4, ASR #1]
  LDR R2, [R5, R4, ROR #1]
  LDR R2, [R5, R4]!
  LDR R2, [R5, R4, LSL #1]!
  LDR R2, [R5, R4, LSR #1]!
  LDR R2, [R5, R4, ASR #1]!
  LDR R2, [R5, R4, ROR #1]!
  LDR R2, [R5], R4
  LDR R2, [R5], R4, LSL #2
  LDR R2, [R5], R4, LSR #2
  LDR R2, [R5], R4, ASR #2
  LDR R2, [R5], R4, ROR #2
  LDR R2, [R5, -R4]
  LDR R2, [R5, -R4, LSL #3]
  LDR R2, [R5, -R4, LSR #3]
  LDR R2, [R5, -R4, ASR #3]
  LDR R2, [R5, -R4, ROR #3]
  LDR R2, [R5, -R4]!
  LDR R2, [R5, -R4, LSL #3]!
  LDR R2, [R5, -R4, LSR #3]!
  LDR R2, [R5, -R4, ASR #3]!
  LDR R2, [R5, -R4, ROR #3]!
  LDR R2, [R5], -R4
  LDR R2, [R5], -R4, LSL #2
  LDR R2, [R5], -R4, LSR #2
  LDR R2, [R5], -R4, ASR #2
  LDR R2, [R5], -R4, ROR #2

  ADD R5, R0, #0x4000
  LDRB R2, [R5, R3]
  LDRB R2, [R5, R4]
  LDRB R2, [R5, R4, LSL #1]
  LDRB R2, [R5, R4, LSR #1]
  LDRB R2, [R5, R4, ASR #1]
  LDRB R2, [R5, R4, ROR #1]
  LDRB R2, [R5, R4]!
  LDRB R2, [R5, R4, LSL #1]!
  LDRB R2, [R5, R4, LSR #1]!
  LDRB R2, [R5, R4, ASR #1]!
  LDRB R2, [R5, R4, ROR #1]!
  LDRB R2, [R5], R4
  LDRB R2, [R5], R4, LSL #2
  LDRB R2, [R5], R4, LSR #2
  LDRB R2, [R5], R4, ASR #2
  LDRB R2, [R5], R4, ROR #2
  LDRB R2, [R5, -R4]
  LDRB R2, [R5, -R4, LSL #3]
  LDRB R2, [R5, -R4, LSR #3]
  LDRB R2, [R5, -R4, ASR #3]
  LDRB R2, [R5, -R4, ROR #3]
  LDRB R2, [R5, -R4]!
  LDRB R2, [R5, -R4, LSL #3]!
  LDRB R2, [R5, -R4, LSR #3]!
  LDRB R2, [R5, -R4, ASR #3]!
  LDRB R2, [R5, -R4, ROR #3]!
  LDRB R2, [R5], -R4
  LDRB R2, [R5], -R4, LSL #2
  LDRB R2, [R5], -R4, LSR #2
  LDRB R2, [R5], -R4, ASR #2
  LDRB R2, [R5], -R4, ROR #2

  ADD R5, R0, #0x5000
  LDRH R2, [R5, R3]
  LDRH R2, [R5, R4]
  LDRH R2, [R5, -R4]
  LDRH R2, [R5], R4
  LDRH R2, [R5], -R4
  LDRH R2, [R5, R4]!
  LDRH R2, [R5, -R4]!

  ADD R5, R0, #0x1000
  LDRSB R2, [R5, R3]
  LDRSB R2, [R5, R4]
  LDRSB R2, [R5, -R4]
  LDRSB R2, [R5], R4
  LDRSB R2, [R5], -R4
  LDRSB R2, [R5, R4]!
  LDRSB R2, [R5, -R4]!

  ADD R5, R0, #0x2000
  LDRSH R2, [R5, R3]
  LDRSH R2, [R5, R4]
  LDRSH R2, [R5, -R4]
  LDRSH R2, [R5], R4
  LDRSH R2, [R5], -R4
  LDRSH R2, [R5, R4]!
  LDRSH R2, [R5, -R4]!

  // STR{, B, H} (reg)
  MOV R3, #0
  MOV R4, #0x300
  STR R2, [R5, R3]
  STR R2, [R5, R4]
  STR R2, [R5, R4, LSL #1]
  STR R2, [R5, R4, LSR #1]
  STR R2, [R5, R4, ASR #1]
  STR R2, [R5, R4, ROR #1]
  STR R2, [R5, R4]!
  STR R2, [R5, R4, LSL #1]!
  STR R2, [R5, R4, LSR #1]!
  STR R2, [R5, R4, ASR #1]!
  STR R2, [R5, R4, ROR #1]!
  STR R2, [R5], R4
  STR R2, [R5], R4, LSL #2
  STR R2, [R5], R4, LSR #2
  STR R2, [R5], R4, ASR #2
  STR R2, [R5], R4, ROR #2
  STR R2, [R5, -R4]
  STR R2, [R5, -R4, LSL #3]
  STR R2, [R5, -R4, LSR #3]
  STR R2, [R5, -R4, ASR #3]
  STR R2, [R5, -R4, ROR #3]
  STR R2, [R5, -R4]!
  STR R2, [R5, -R4, LSL #3]!
  STR R2, [R5, -R4, LSR #3]!
  STR R2, [R5, -R4, ASR #3]!
  STR R2, [R5, -R4, ROR #3]!
  STR R2, [R5], -R4
  STR R2, [R5], -R4, LSL #2
  STR R2, [R5], -R4, LSR #2
  STR R2, [R5], -R4, ASR #2
  STR R2, [R5], -R4, ROR #2

  STRB R2, [R5, R3]
  STRB R2, [R5, R4]
  STRB R2, [R5, R4, LSL #1]
  STRB R2, [R5, R4, LSR #1]
  STRB R2, [R5, R4, ASR #1]
  STRB R2, [R5, R4, ROR #1]
  STRB R2, [R5, R4]!
  STRB R2, [R5, R4, LSL #1]!
  STRB R2, [R5, R4, LSR #1]!
  STRB R2, [R5, R4, ASR #1]!
  STRB R2, [R5, R4, ROR #1]!
  STRB R2, [R5], R4
  STRB R2, [R5], R4, LSL #2
  STRB R2, [R5], R4, LSR #2
  STRB R2, [R5], R4, ASR #2
  STRB R2, [R5], R4, ROR #2
  STRB R2, [R5, -R4]
  STRB R2, [R5, -R4, LSL #3]
  STRB R2, [R5, -R4, LSR #3]
  STRB R2, [R5, -R4, ASR #3]
  STRB R2, [R5, -R4, ROR #3]
  STRB R2, [R5, -R4]!
  STRB R2, [R5, -R4, LSL #3]!
  STRB R2, [R5, -R4, LSR #3]!
  STRB R2, [R5, -R4, ASR #3]!
  STRB R2, [R5, -R4, ROR #3]!
  STRB R2, [R5], -R4
  STRB R2, [R5], -R4, LSL #2
  STRB R2, [R5], -R4, LSR #2
  STRB R2, [R5], -R4, ASR #2
  STRB R2, [R5], -R4, ROR #2

  ADD R7, R0, #0x6000
  STRH R2, [R7, R3]
  STRH R2, [R7, R4]
  STRH R2, [R7, -R4]
  STRH R2, [R7], R4
  STRH R2, [R7], -R4
  STRH R2, [R7, R4]!
  STRH R2, [R7, -R4]!

  // LDRD, STRD (imm)
  LDRD R2, R3, [R7]
  LDRD R2, R3, [R7, #4]
  LDRD R2, R3, [R7, #-4]
  LDRD R2, R3, [R7, #0xFC]
  LDRD R2, R3, [R7, #-0xFC]
  LDRD R2, R3, [R7, #4]!
  LDRD R2, R3, [R7, #-4]!
  LDRD R2, R3, [R7, #0xFC]!
  LDRD R2, R3, [R7, #-0xFC]!
  LDRD R2, R3, [R7], #4
  LDRD R2, R3, [R7], #-4
  LDRD R2, R3, [R7], #0xFC
  LDRD R2, R3, [R7], #-0xFC

  STRD R2, R3, [R7]
  STRD R2, R3, [R7, #4]
  STRD R2, R3, [R7, #-4]
  STRD R2, R3, [R7, #0xFC]
  STRD R2, R3, [R7, #-0xFC]
  STRD R2, R3, [R7, #4]!
  STRD R2, R3, [R7, #-4]!
  STRD R2, R3, [R7, #0xFC]!
  STRD R2, R3, [R7, #-0xFC]!
  STRD R2, R3, [R7], #4
  STRD R2, R3, [R7], #-4
  STRD R2, R3, [R7], #0xFC
  STRD R2, R3, [R7], #-0xFC

  // LDRD, STRD (reg)
  MOV R3, #0
  MOV R4, #0x300
  LDRD R8, R9, [R7, R3]
  LDRD R8, R9, [R7, R4]
  LDRD R8, R9, [R7, -R4]
  LDRD R8, R9, [R7, R4]!
  LDRD R8, R9, [R7, -R4]!
  LDRD R8, R9, [R7], R4
  LDRD R8, R9, [R7], -R4

  STRD R8, R9, [R7, R3]
  STRD R8, R9, [R7, R4]
  STRD R8, R9, [R7, -R4]
  STRD R8, R9, [R7, R4]!
  STRD R8, R9, [R7, -R4]!
  STRD R8, R9, [R7], R4
  STRD R8, R9, [R7], -R4

  // LDM, STM
  ADD R5, R0, #0x400
  STMEA R5, {R2}
  LDMEA R5, {R2}
  STMEA R5!, {R0-R4, R6-R12, LR}
  LDMEA R5!, {R0-R4, R6-R12, LR}
  STMED R5, {R3}
  LDMED R5, {R3}
  STMED R5!, {R0-R4, R6-R12, LR}
  LDMED R5!, {R0-R4, R6-R12, LR}
  STMFA R5, {R4}
  LDMFA R5, {R4}
  STMFA R5!, {R0-R4, R6-R12, LR}
  LDMFA R5!, {R0-R4, R6-R12, LR}
  STMFD R5, {R6}
  LDMFD R5, {R6}
  STMFD R5!, {R0-R4, R6-R12, LR}
  LDMFD R5!, {R0-R4, R6-R12, LR}

  // PUSH, POP
  PUSH {R0}
  PUSH {R3-R5}
  POP  {R3-R5}
  POP  {R0}
  PUSH {R0-R12, LR}
  POP  {R0-R12, LR}

  // LDREX{, B, H, D}
  LDREX R2, [R0]
  LDREXB R2, [R0]
  LDREXH R2, [R0]
  LDREXD R2, [R0]
  CLREX

  // VLDR, VSTR
  ADD R4, R0, #0x800
  VLDR S0, [R4]
  VLDR S0, [R4, #32]
  VLDR S0, [R4, #-32]
  VLDR S0, [R4, #0x3FC]
  VLDR S0, [R4, #-0x3FC]
  VSTR S0, [R4]
  VSTR S0, [R4, #32]
  VSTR S0, [R4, #-32]
  VSTR S0, [R4, #0x3FC]
  VSTR S0, [R4, #-0x3FC]

  VLDR D0, [R4]
  VLDR D0, [R4, #32]
  VLDR D0, [R4, #-32]
  VLDR D0, [R4, #0x3FC]
  VLDR D0, [R4, #-0x3FC]
  VSTR D0, [R4]
  VSTR D0, [R4, #32]
  VSTR D0, [R4, #-32]
  VSTR D0, [R4, #0x3FC]
  VSTR D0, [R4, #-0x3FC]

  // VLDM, VSTM
  VSTM R0, {S1}
  VLDM R0, {S1}
  VSTM R0, {S0-S31}
  VLDM R0, {S0-S31}
  VSTM R0, {D1}
  VLDM R0, {D1}
  VSTM R0, {D0-D15}
  VLDM R0, {D0-D15}

  // VPUSH, VPOP
  VPUSH {S0}
  VPUSH {D0}
  VPUSH {S0-S31}
  VPUSH {D0-D15}
  VPOP {D0-D15}
  VPOP {S0-S31}
  VPOP {D0}
  VPOP {S0}

  // VLD1 / VST1
  ADD R2, R0, #0x8000
  MOV R3, #0x20
  MOV R4, #0x40
  VLD1.8 D0[2], [R2]
  VLD1.8 D0[1], [R2]!
  VLD1.8 D0[0], [R2], R3
  VLD1.16 D0[2], [R2]
  VLD1.16 D0[1], [R2]!
  VLD1.16 D0[0], [R2], R4
  VLD1.32 D0[0], [R2]
  VLD1.32 D0[1], [R2]!
  VLD1.32 D0[0], [R2], R3

  VLD1.8  {D2[]}, [R2]
  VLD1.8  {D2[]}, [R2]!
  VLD1.8  {D2[]}, [R2], R3
  VLD1.16 {D2[]}, [R2]
  VLD1.16 {D2[]}, [R2]!
  VLD1.16 {D2[]}, [R2], R4
  VLD1.32 {D2[]}, [R2]
  VLD1.32 {D2[]}, [R2]!
  VLD1.32 {D2[]}, [R2], R3

  VLD1.8  {D1}, [R2]
  VLD1.8  {D1-D2}, [R2]
  VLD1.8  {D1-D3}, [R2]
  VLD1.8  {D1-D4}, [R2]
  VLD1.8  {D1}, [R2]!
  VLD1.8  {D1-D2}, [R2]!
  VLD1.8  {D1-D3}, [R2]!
  VLD1.8  {D1-D4}, [R2]!
  VLD1.8  {D1}, [R2], R3
  VLD1.8  {D1-D2}, [R2], R3
  VLD1.8  {D1-D3}, [R2], R3
  VLD1.8  {D1-D4}, [R2], R3
  VLD1.16 {D1}, [R2]
  VLD1.16 {D1-D2}, [R2]
  VLD1.16 {D1-D3}, [R2]
  VLD1.16 {D1-D4}, [R2]
  VLD1.16 {D1}, [R2]!
  VLD1.16 {D1-D2}, [R2]!
  VLD1.16 {D1-D3}, [R2]!
  VLD1.16 {D1-D4}, [R2]!
  VLD1.16 {D1}, [R2], R4
  VLD1.16 {D1-D2}, [R2], R4
  VLD1.16 {D1-D3}, [R2], R4
  VLD1.16 {D1-D4}, [R2], R4
  VLD1.32 {D1}, [R2]
  VLD1.32 {D1-D2}, [R2]
  VLD1.32 {D1-D3}, [R2]
  VLD1.32 {D1-D4}, [R2]
  VLD1.32 {D1}, [R2]!
  VLD1.32 {D1-D2}, [R2]!
  VLD1.32 {D1-D3}, [R2]!
  VLD1.32 {D1-D4}, [R2]!
  VLD1.32 {D1}, [R2], R3
  VLD1.32 {D1-D2}, [R2], R3
  VLD1.32 {D1-D3}, [R2], R3
  VLD1.32 {D1-D4}, [R2], R3

  VST1.8 D0[2], [R2]
  VST1.8 D0[1], [R2]!
  VST1.8 D0[0], [R2], R3
  VST1.16 D0[2], [R2]
  VST1.16 D0[1], [R2]!
  VST1.16 D0[0], [R2], R4
  VST1.32 D0[0], [R2]
  VST1.32 D0[1], [R2]!
  VST1.32 D0[0], [R2], R3

  VST1.8  {D1}, [R2]
  VST1.8  {D1-D2}, [R2]
  VST1.8  {D1-D3}, [R2]
  VST1.8  {D1-D4}, [R2]
  VST1.8  {D1}, [R2]!
  VST1.8  {D1-D2}, [R2]!
  VST1.8  {D1-D3}, [R2]!
  VST1.8  {D1-D4}, [R2]!
  VST1.8  {D1}, [R2], R3
  VST1.8  {D1-D2}, [R2], R3
  VST1.8  {D1-D3}, [R2], R3
  VST1.8  {D1-D4}, [R2], R3
  VST1.16 {D1}, [R2]
  VST1.16 {D1-D2}, [R2]
  VST1.16 {D1-D3}, [R2]
  VST1.16 {D1-D4}, [R2]
  VST1.16 {D1}, [R2]!
  VST1.16 {D1-D2}, [R2]!
  VST1.16 {D1-D3}, [R2]!
  VST1.16 {D1-D4}, [R2]!
  VST1.16 {D1}, [R2], R4
  VST1.16 {D1-D2}, [R2], R4
  VST1.16 {D1-D3}, [R2], R4
  VST1.16 {D1-D4}, [R2], R4
  VST1.32 {D1}, [R2]
  VST1.32 {D1-D2}, [R2]
  VST1.32 {D1-D3}, [R2]
  VST1.32 {D1-D4}, [R2]
  VST1.32 {D1}, [R2]!
  VST1.32 {D1-D2}, [R2]!
  VST1.32 {D1-D3}, [R2]!
  VST1.32 {D1-D4}, [R2]!
  VST1.32 {D1}, [R2], R3
  VST1.32 {D1-D2}, [R2], R3
  VST1.32 {D1-D3}, [R2], R3
  VST1.32 {D1-D4}, [R2], R3

  // VLD2 / VST2
  VLD2.8  {D0[2], D1[2]}, [R2]
  VLD2.8  {D0[1], D1[1]}, [R2]!
  VLD2.8  {D0[0], D1[0]}, [R2], R3
  VLD2.16 {D0[2], D1[2]}, [R2]
  VLD2.16 {D0[1], D1[1]}, [R2]!
  VLD2.16 {D0[0], D1[0]}, [R2], R4
  VLD2.32 {D0[0], D1[0]}, [R2]
  VLD2.32 {D0[1], D1[1]}, [R2]!
  VLD2.32 {D0[0], D1[0]}, [R2], R3

  VLD2.8  {D2[], D3[]}, [R2]
  VLD2.8  {D2[], D3[]}, [R2]!
  VLD2.8  {D2[], D3[]}, [R2], R3
  VLD2.16 {D2[], D3[]}, [R2]
  VLD2.16 {D2[], D3[]}, [R2]!
  VLD2.16 {D2[], D3[]}, [R2], R4
  VLD2.32 {D2[], D3[]}, [R2]
  VLD2.32 {D2[], D3[]}, [R2]!
  VLD2.32 {D2[], D3[]}, [R2], R3

  VLD2.8  {D1-D2}, [R2]
  VLD2.8  {D1-D4}, [R2]
  VLD2.8  {D1-D2}, [R2]!
  VLD2.8  {D1-D4}, [R2]!
  VLD2.8  {D1-D2}, [R2], R3
  VLD2.8  {D1-D4}, [R2], R3
  VLD2.16 {D1-D2}, [R2]
  VLD2.16 {D1-D4}, [R2]
  VLD2.16 {D1-D2}, [R2]!
  VLD2.16 {D1-D4}, [R2]!
  VLD2.16 {D1-D2}, [R2], R4
  VLD2.16 {D1-D4}, [R2], R4
  VLD2.32 {D1-D2}, [R2]
  VLD2.32 {D1-D4}, [R2]
  VLD2.32 {D1-D2}, [R2]!
  VLD2.32 {D1-D4}, [R2]!
  VLD2.32 {D1-D2}, [R2], R3
  VLD2.32 {D1-D4}, [R2], R3

  VST2.8  {D0[2], D1[2]}, [R2]
  VST2.8  {D0[1], D1[1]}, [R2]!
  VST2.8  {D0[0], D1[0]}, [R2], R3
  VST2.16 {D0[2], D1[2]}, [R2]
  VST2.16 {D0[1], D1[1]}, [R2]!
  VST2.16 {D0[0], D1[0]}, [R2], R4
  VST2.32 {D0[0], D1[0]}, [R2]
  VST2.32 {D0[1], D1[1]}, [R2]!
  VST2.32 {D0[0], D1[0]}, [R2], R3

  VST2.8  {D1-D2}, [R2]
  VST2.8  {D1-D4}, [R2]
  VST2.8  {D1-D2}, [R2]!
  VST2.8  {D1-D4}, [R2]!
  VST2.8  {D1-D2}, [R2], R3
  VST2.8  {D1-D4}, [R2], R3
  VST2.16 {D1-D2}, [R2]
  VST2.16 {D1-D4}, [R2]
  VST2.16 {D1-D2}, [R2]!
  VST2.16 {D1-D4}, [R2]!
  VST2.16 {D1-D2}, [R2], R4
  VST2.16 {D1-D4}, [R2], R4
  VST2.32 {D1-D2}, [R2]
  VST2.32 {D1-D4}, [R2]
  VST2.32 {D1-D2}, [R2]!
  VST2.32 {D1-D4}, [R2]!
  VST2.32 {D1-D2}, [R2], R3
  VST2.32 {D1-D4}, [R2], R3

  // VLD3 / VST3
  VLD3.8  {D0[2], D1[2], D2[2]}, [R2]
  VLD3.8  {D0[1], D1[1], D2[1]}, [R2]!
  VLD3.8  {D0[0], D1[0], D2[0]}, [R2], R3
  VLD3.16 {D0[2], D1[2], D2[2]}, [R2]
  VLD3.16 {D0[1], D1[1], D2[1]}, [R2]!
  VLD3.16 {D0[0], D1[0], D2[0]}, [R2], R4
  VLD3.32 {D0[0], D1[0], D2[0]}, [R2]
  VLD3.32 {D0[1], D1[1], D2[1]}, [R2]!
  VLD3.32 {D0[0], D1[0], D2[0]}, [R2], R3

  VLD3.8  {D2[], D3[], D4[]}, [R2]
  VLD3.8  {D2[], D3[], D4[]}, [R2]!
  VLD3.8  {D2[], D3[], D4[]}, [R2], R3
  VLD3.16 {D2[], D3[], D4[]}, [R2]
  VLD3.16 {D2[], D3[], D4[]}, [R2]!
  VLD3.16 {D2[], D3[], D4[]}, [R2], R4
  VLD3.32 {D2[], D3[], D4[]}, [R2]
  VLD3.32 {D2[], D3[], D4[]}, [R2]!
  VLD3.32 {D2[], D3[], D4[]}, [R2], R3

  VLD3.8  {D1-D3}, [R2]
  VLD3.8  {D1-D3}, [R2]!
  VLD3.8  {D1-D3}, [R2], R3
  VLD3.16 {D1-D3}, [R2]
  VLD3.16 {D1-D3}, [R2]!
  VLD3.16 {D1-D3}, [R2], R4
  VLD3.32 {D1-D3}, [R2]
  VLD3.32 {D1-D3}, [R2]!
  VLD3.32 {D1-D3}, [R2], R3

  VST3.8  {D0[2], D1[2], D2[2]}, [R2]
  VST3.8  {D0[1], D1[1], D2[1]}, [R2]!
  VST3.8  {D0[0], D1[0], D2[0]}, [R2], R3
  VST3.16 {D0[2], D1[2], D2[2]}, [R2]
  VST3.16 {D0[1], D1[1], D2[1]}, [R2]!
  VST3.16 {D0[0], D1[0], D2[0]}, [R2], R4
  VST3.32 {D0[0], D1[0], D2[0]}, [R2]
  VST3.32 {D0[1], D1[1], D2[1]}, [R2]!
  VST3.32 {D0[0], D1[0], D2[0]}, [R2], R3

  VST3.8  {D1-D3}, [R2]
  VST3.8  {D1-D3}, [R2]!
  VST3.8  {D1-D3}, [R2], R3
  VST3.16 {D1-D3}, [R2]
  VST3.16 {D1-D3}, [R2]!
  VST3.16 {D1-D3}, [R2], R4
  VST3.32 {D1-D3}, [R2]
  VST3.32 {D1-D3}, [R2]!
  VST3.32 {D1-D3}, [R2], R3

  // VLD4 / VST4
  VLD4.8  {D0[2], D1[2], D2[2], D3[2]}, [R2]
  VLD4.8  {D0[1], D1[1], D2[1], D3[1]}, [R2]!
  VLD4.8  {D0[0], D1[0], D2[0], D3[0]}, [R2], R3
  VLD4.16 {D0[2], D1[2], D2[2], D3[2]}, [R2]
  VLD4.16 {D0[1], D1[1], D2[1], D3[1]}, [R2]!
  VLD4.16 {D0[0], D1[0], D2[0], D3[0]}, [R2], R4
  VLD4.32 {D0[0], D1[0], D2[0], D3[0]}, [R2]
  VLD4.32 {D0[1], D1[1], D2[1], D3[1]}, [R2]!
  VLD4.32 {D0[0], D1[0], D2[0], D3[0]}, [R2], R3

  VLD4.8  {D2[], D3[], D4[], D5[]}, [R2]
  VLD4.8  {D2[], D3[], D4[], D5[]}, [R2]!
  VLD4.8  {D2[], D3[], D4[], D5[]}, [R2], R3
  VLD4.16 {D2[], D3[], D4[], D5[]}, [R2]
  VLD4.16 {D2[], D3[], D4[], D5[]}, [R2]!
  VLD4.16 {D2[], D3[], D4[], D5[]}, [R2], R4
  VLD4.32 {D2[], D3[], D4[], D5[]}, [R2]
  VLD4.32 {D2[], D3[], D4[], D5[]}, [R2]!
  VLD4.32 {D2[], D3[], D4[], D5[]}, [R2], R3

  VLD4.8  {D1-D4}, [R2]
  VLD4.8  {D1-D4}, [R2]!
  VLD4.8  {D1-D4}, [R2], R3
  VLD4.16 {D1-D4}, [R2]
  VLD4.16 {D1-D4}, [R2]!
  VLD4.16 {D1-D4}, [R2], R4
  VLD4.32 {D1-D4}, [R2]
  VLD4.32 {D1-D4}, [R2]!
  VLD4.32 {D1-D4}, [R2], R3

  VST4.8  {D0[2], D1[2], D2[2], D3[2]}, [R2]
  VST4.8  {D0[1], D1[1], D2[1], D3[1]}, [R2]!
  VST4.8  {D0[0], D1[0], D2[0], D3[0]}, [R2], R3
  VST4.16 {D0[2], D1[2], D2[2], D3[2]}, [R2]
  VST4.16 {D0[1], D1[1], D2[1], D3[1]}, [R2]!
  VST4.16 {D0[0], D1[0], D2[0], D3[0]}, [R2], R4
  VST4.32 {D0[0], D1[0], D2[0], D3[0]}, [R2]
  VST4.32 {D0[1], D1[1], D2[1], D3[1]}, [R2]!
  VST4.32 {D0[0], D1[0], D2[0], D3[0]}, [R2], R3

  VST4.8  {D1-D4}, [R2]
  VST4.8  {D1-D4}, [R2]!
  VST4.8  {D1-D4}, [R2], R3
  VST4.16 {D1-D4}, [R2]
  VST4.16 {D1-D4}, [R2]!
  VST4.16 {D1-D4}, [R2], R4
  VST4.32 {D1-D4}, [R2]
  VST4.32 {D1-D4}, [R2]!
  VST4.32 {D1-D4}, [R2], R3

  // Literal loads - will not trap
  MOV R2, #16
  LDR R3, lita32
  LDR R3, [PC, R2]
  LDRB R3, lita32
  LDRB R3, [PC, R2]
  LDRHEQ R4, lita32
  LDRH R4, [PC, R2]
  LDRSB R5, lita32
  LDRSB R5, [PC, R2]
  LDRSH R6, lita32
  LDRSH R6, [PC, R2]
  LDRD R6, lita32
  LDRD R6, [PC, R2]

  MOV SP, R12
  POP {R4-R12, PC}
.endfunc

lita32: .quad 0

.global end_test_a32
end_test_a32:

#elif __aarch64__
.global test_a64
.func
.type test_a64, %function

test_a64:
  MOV X29, SP
  MOV SP, X1

  // LDRI {, B, H, SB, SH, SW}
  ADD X4, X0, #0x400
  LDR   X2, [X4]
  LDR   X2, [X4, #8]
  LDR   X2, [X4, #7]
  LDR   X2, [X4, #-5]
  LDR   X2, [X4, #32760]
  LDR   X2, [X4, #255]
  LDR   X2, [X4, #-256]
  LDR   X2, [X4, #0]!
  LDR   X2, [X4, #255]!
  LDR   X2, [X4, #-256]!
  LDR   X2, [X4], #0
  LDR   X2, [X4], #1
  LDR   X2, [X4], #255
  LDR   X2, [X4], #-256

  LDR   B0, [X4]
  LDR   B0, [X4, #8]
  LDR   B0, [X4, #7]
  LDR   B0, [X4, #-5]
  LDR   B0, [X4, #4095]
  LDR   B0, [X4, #255]
  LDR   B0, [X4, #-256]
  LDR   B0, [X4, #0]!
  LDR   B0, [X4, #255]!
  LDR   B0, [X4, #-256]!
  LDR   B0, [X4], #0
  LDR   B0, [X4], #1
  LDR   B0, [X4], #255
  LDR   B0, [X4], #-256

  LDR   H0, [X4]
  LDR   H0, [X4, #8]
  LDR   H0, [X4, #7]
  LDR   H0, [X4, #-5]
  LDR   H0, [X4, #8190]
  LDR   H0, [X4, #255]
  LDR   H0, [X4, #-256]
  LDR   H0, [X4, #0]!
  LDR   H0, [X4, #255]!
  LDR   H0, [X4, #-256]!
  LDR   H0, [X4], #0
  LDR   H0, [X4], #1
  LDR   H0, [X4], #255
  LDR   H0, [X4], #-256

  LDR   S0, [X4]
  LDR   S0, [X4, #8]
  LDR   S0, [X4, #7]
  LDR   S0, [X4, #-5]
  LDR   S0, [X4, #16380]
  LDR   S0, [X4, #255]
  LDR   S0, [X4, #-256]
  LDR   S0, [X4, #0]!
  LDR   S0, [X4, #255]!
  LDR   S0, [X4, #-256]!
  LDR   S0, [X4], #0
  LDR   S0, [X4], #1
  LDR   S0, [X4], #255
  LDR   S0, [X4], #-256

  LDR   D0, [X4]
  LDR   D0, [X4, #8]
  LDR   D0, [X4, #7]
  LDR   D0, [X4, #-5]
  LDR   D0, [X4, #32760]
  LDR   D0, [X4, #255]
  LDR   D0, [X4, #-256]
  LDR   D0, [X4, #0]!
  LDR   D0, [X4, #255]!
  LDR   D0, [X4, #-256]!
  LDR   D0, [X4], #0
  LDR   D0, [X4], #1
  LDR   D0, [X4], #255
  LDR   D0, [X4], #-256

  LDR   Q0, [X4]
  LDR   Q0, [X4, #8]
  LDR   Q0, [X4, #7]
  LDR   Q0, [X4, #-5]
  LDR   Q0, [X4, #65520]
  LDR   Q0, [X4, #255]
  LDR   Q0, [X4, #-256]
  LDR   Q0, [X4, #0]!
  LDR   Q0, [X4, #255]!
  LDR   Q0, [X4, #-256]!
  LDR   Q0, [X4], #0
  LDR   Q0, [X4], #1
  LDR   Q0, [X4], #255
  LDR   Q0, [X4], #-256

  ADD X4, X4, #0x30
  LDR   W3, [X4]
  LDR   W3, [X4, #8]
  LDR   W3, [X4, #7]
  LDR   W3, [X4, #-5]
  LDR   W3, [X4, #16380]
  LDR   W3, [X4, #255]
  LDR   W3, [X4, #-256]
  LDR   W3, [X4, #0]!
  LDR   W3, [X4, #255]!
  LDR   W3, [X4, #-256]!
  LDR   W3, [X4], #0
  LDR   W3, [X4], #1
  LDR   W3, [X4], #255
  LDR   W3, [X4], #-256

  ADD X4, X4, #0x30
  LDRB  W3, [X4]
  LDRB  W3, [X4, #8]
  LDRB  W3, [X4, #7]
  LDRB  W3, [X4, #-5]
  LDRB  W3, [X4, #4095]
  LDRB  W3, [X4, #255]
  LDRB  W3, [X4, #-256]
  LDRB  W3, [X4, #0]!
  LDRB  W3, [X4, #255]!
  LDRB  W3, [X4, #-256]!
  LDRB  W3, [X4], #0
  LDRB  W3, [X4], #1
  LDRB  W3, [X4], #255
  LDRB  W3, [X4], #-256

  ADD X4, X4, #0x30
  LDRH  W3, [X4]
  LDRH  W3, [X4, #8]
  LDRH  W3, [X4, #7]
  LDRH  W3, [X4, #-5]
  LDRH  W3, [X4, #8190]
  LDRH  W3, [X4, #255]
  LDRH  W3, [X4, #-256]
  LDRH  W3, [X4, #0]!
  LDRH  W3, [X4, #255]!
  LDRH  W3, [X4, #-256]!
  LDRH  W3, [X4], #0
  LDRH  W3, [X4], #1
  LDRH  W3, [X4], #255
  LDRH  W3, [X4], #-256

  ADD X4, X4, #0x30
  LDRSB X2, [X4]
  LDRSB X2, [X4, #8]
  LDRSB X2, [X4, #7]
  LDRSB X2, [X4, #-5]
  LDRSB X2, [X4, #4095]
  LDRSB X2, [X4, #255]
  LDRSB X2, [X4, #-256]
  LDRSB X2, [X4, #0]!
  LDRSB X2, [X4, #255]!
  LDRSB X2, [X4, #-256]!
  LDRSB X2, [X4], #0
  LDRSB X2, [X4], #1
  LDRSB X2, [X4], #255
  LDRSB X2, [X4], #-256

  ADD X4, X4, #0x30
  LDRSB W3, [X4]
  LDRSB W3, [X4, #8]
  LDRSB W3, [X4, #7]
  LDRSB W3, [X4, #-5]
  LDRSB W3, [X4, #4095]
  LDRSB W3, [X4, #255]
  LDRSB W3, [X4, #-256]
  LDRSB W3, [X4, #0]!
  LDRSB W3, [X4, #255]!
  LDRSB W3, [X4, #-256]!
  LDRSB W3, [X4], #0
  LDRSB W3, [X4], #1
  LDRSB W3, [X4], #255
  LDRSB W3, [X4], #-256

  ADD X4, X4, #0x30
  LDRSH X2, [X4]
  LDRSH X2, [X4, #8]
  LDRSH X2, [X4, #7]
  LDRSH X2, [X4, #-5]
  LDRSH X2, [X4, #8190]
  LDRSH X2, [X4, #255]
  LDRSH X2, [X4, #-256]
  LDRSH X2, [X4, #0]!
  LDRSH X2, [X4, #255]!
  LDRSH X2, [X4, #-256]!
  LDRSH X2, [X4], #0
  LDRSH X2, [X4], #1
  LDRSH X2, [X4], #255
  LDRSH X2, [X4], #-256

  ADD X4, X4, #0x30
  LDRSH W3, [X4]
  LDRSH W3, [X4, #8]
  LDRSH W3, [X4, #7]
  LDRSH W3, [X4, #-5]
  LDRSH W3, [X4, #8190]
  LDRSH W3, [X4, #255]
  LDRSH W3, [X4, #-256]
  LDRSH W3, [X4, #0]!
  LDRSH W3, [X4, #255]!
  LDRSH W3, [X4, #-256]!
  LDRSH W3, [X4], #0
  LDRSH W3, [X4], #1
  LDRSH W3, [X4], #255
  LDRSH W3, [X4], #-256

  ADD X4, X4, #0x30
  LDRSW X2, [X4]
  LDRSW X2, [X4, #8]
  LDRSW X2, [X4, #7]
  LDRSW X2, [X4, #-5]
  LDRSW X2, [X4, #16380]
  LDRSW X2, [X4, #255]
  LDRSW X2, [X4, #-256]
  LDRSW X2, [X4, #0]!
  LDRSW X2, [X4, #255]!
  LDRSW X2, [X4, #-256]!
  LDRSW X2, [X4], #0
  LDRSW X2, [X4], #1
  LDRSW X2, [X4], #255
  LDRSW X2, [X4], #-256


  // LDR {, B, H, SB, SH, SW}
  ADD X5, X0, #0x800
  MOV X6, #0
  MOV X7, #0x200
  LDR X2, [X5, X6]
  LDR X2, [X5, X7]
  LDR X2, [X5, X7, LSL #3]
  LDR X2, [X5, W7, UXTW #0]
  LDR X2, [X5, W7, UXTW #3]
  LDR X2, [X5, W7, SXTW #0]
  LDR X2, [X5, W7, SXTW #3]
  LDR X2, [X5, X7, SXTX #0]
  LDR X2, [X5, X7, SXTX #3]

  LDR B1, [X5, X6]
  LDR B1, [X5, X7]
  LDR B1, [X5, X7, LSL #0]
  LDR B1, [X5, W7, UXTW #0]
  LDR B1, [X5, W7, SXTW #0]
  LDR B1, [X5, X7, SXTX #0]

  LDR H2, [X5, X6]
  LDR H2, [X5, X7]
  LDR H2, [X5, X7, LSL #1]
  LDR H2, [X5, W7, UXTW #0]
  LDR H2, [X5, W7, UXTW #1]
  LDR H2, [X5, W7, SXTW #0]
  LDR H2, [X5, W7, SXTW #1]
  LDR H2, [X5, X7, SXTX #0]
  LDR H2, [X5, X7, SXTX #1]

  LDR S3, [X5, X6]
  LDR S3, [X5, X7]
  LDR S3, [X5, X7, LSL #2]
  LDR S3, [X5, W7, UXTW #0]
  LDR S3, [X5, W7, UXTW #2]
  LDR S3, [X5, W7, SXTW #0]
  LDR S3, [X5, W7, SXTW #2]
  LDR S3, [X5, X7, SXTX #0]
  LDR S3, [X5, X7, SXTX #2]

  LDR D4, [X5, X6]
  LDR D4, [X5, X7]
  LDR D4, [X5, X7, LSL #3]
  LDR D4, [X5, W7, UXTW #0]
  LDR D4, [X5, W7, UXTW #3]
  LDR D4, [X5, W7, SXTW #0]
  LDR D4, [X5, W7, SXTW #3]
  LDR D4, [X5, X7, SXTX #0]
  LDR D4, [X5, X7, SXTX #3]

  LDR Q0, [X5, X6]
  LDR Q0, [X5, X7]
  LDR Q0, [X5, X7, LSL #4]
  LDR Q0, [X5, W7, UXTW #0]
  LDR Q0, [X5, W7, UXTW #4]
  LDR Q0, [X5, W7, SXTW #0]
  LDR Q0, [X5, W7, SXTW #4]
  LDR Q0, [X5, X7, SXTX #0]
  LDR Q0, [X5, X7, SXTX #4]

  ADD X5, X5, #0x40
  LDRB W3, [X5, X6]
  LDRB W3, [X5, X7]
  LDRB W3, [X5, W7, UXTW #0]
  LDRB W3, [X5, W7, SXTW #0]
  LDRB W3, [X5, X7, SXTX #0]

  ADD X5, X5, #0x40
  LDRH w3, [X5, X6]
  LDRH w3, [X5, X7]
  LDRH w3, [X5, X7, LSL #1]
  LDRH w3, [X5, W7, UXTW #0]
  LDRH w3, [X5, W7, UXTW #1]
  LDRH w3, [X5, W7, SXTW #0]
  LDRH w3, [X5, W7, SXTW #1]
  LDRH w3, [X5, X7, SXTX #0]
  LDRH w3, [X5, X7, SXTX #1]

  ADD X5, X5, #0x40
  LDRSB X2, [X5, X6]
  LDRSB X2, [X5, X7]
  LDRSB X2, [X5, X7, LSL #0]
  LDRSB X2, [X5, W7, UXTW #0]
  LDRSB X2, [X5, W7, SXTW #0]
  LDRSB X2, [X5, X7, SXTX #0]

  ADD X5, X5, #0x40
  LDRSB W3, [X5, X6]
  LDRSB W3, [X5, X7]
  LDRSB W3, [X5, X7, LSL #0]
  LDRSB W3, [X5, W7, UXTW #0]
  LDRSB W3, [X5, W7, SXTW #0]
  LDRSB W3, [X5, X7, SXTX #0]

  ADD X5, X5, #0x40
  LDRSH X2, [X5, X6]
  LDRSH X2, [X5, X7]
  LDRSH X2, [X5, X7, LSL #0]
  LDRSH X2, [X5, X7, LSL #1]
  LDRSH X2, [X5, W7, UXTW #0]
  LDRSH X2, [X5, W7, UXTW #1]
  LDRSH X2, [X5, W7, SXTW #0]
  LDRSH X2, [X5, W7, SXTW #1]
  LDRSH X2, [X5, X7, SXTX #0]
  LDRSH X2, [X5, X7, SXTX #1]

  ADD X5, X5, #0x40
  LDRSH W3, [X5, X6]
  LDRSH W3, [X5, X7]
  LDRSH W3, [X5, X7, LSL #0]
  LDRSH W3, [X5, X7, LSL #1]
  LDRSH W3, [X5, W7, UXTW #0]
  LDRSH W3, [X5, W7, UXTW #1]
  LDRSH W3, [X5, W7, SXTW #0]
  LDRSH W3, [X5, W7, SXTW #1]
  LDRSH W3, [X5, X7, SXTX #0]
  LDRSH W3, [X5, X7, SXTX #1]

  ADD X5, X5, #0x40
  LDRSW X2, [X5, X6]
  LDRSW X2, [X5, X7]
  LDRSW X2, [X5, X7, LSL #0]
  LDRSW X2, [X5, X7, LSL #2]
  LDRSW X2, [X5, W7, UXTW #0]
  LDRSW X2, [X5, W7, UXTW #2]
  LDRSW X2, [X5, W7, SXTW #0]
  LDRSW X2, [X5, W7, SXTW #2]
  LDRSW X2, [X5, X7, SXTX #0]
  LDRSW X2, [X5, X7, SXTX #2]


  // LDRT {, B, H, SB, SH, SW}
  ADD X6, X0, #0x700
  LDTR X2, [X6]
  LDTR X2, [X6, #8]
  LDTR X2, [X6, #-6]
  LDTR X2, [X6, #255]
  LDTR X2, [X6, #-256]

  ADD X6, X6, #0x80
  LDTRB W3, [X6]
  LDTRB W3, [X6, #8]
  LDTRB W3, [X6, #-6]
  LDTRB W3, [X6, #255]
  LDTRB W3, [X6, #-256]

  ADD X6, X6, #0x80
  LDTRH W3, [X6]
  LDTRH W3, [X6, #8]
  LDTRH W3, [X6, #-6]
  LDTRH W3, [X6, #255]
  LDTRH W3, [X6, #-256]

  ADD X6, X6, #0x80
  LDTRSB X2, [X6]
  LDTRSB X2, [X6, #8]
  LDTRSB X2, [X6, #-6]
  LDTRSB X2, [X6, #255]
  LDTRSB X2, [X6, #-256]

  ADD X6, X6, #0x80
  LDTRSB W3, [X6]
  LDTRSB W3, [X6, #8]
  LDTRSB W3, [X6, #-6]
  LDTRSB W3, [X6, #255]
  LDTRSB W3, [X6, #-256]

  ADD X6, X6, #0x80
  LDTRSH X2, [X6]
  LDTRSH X2, [X6, #8]
  LDTRSH X2, [X6, #-6]
  LDTRSH X2, [X6, #255]
  LDTRSH X2, [X6, #-256]

  ADD X6, X6, #0x80
  LDTRSH W3, [X6]
  LDTRSH W3, [X6, #8]
  LDTRSH W3, [X6, #-6]
  LDTRSH W3, [X6, #255]
  LDTRSH W3, [X6, #-256]


  // STRI {, B, H}
  ADD X4, X0, #0x400
  STR   X2, [X4]
  STR   X2, [X4, #8]
  STR   X2, [X4, #7]
  STR   X2, [X4, #-5]
  STR   X2, [X4, #32760]
  STR   X2, [X4, #255]
  STR   X2, [X4, #-256]
  STR   X2, [X4, #0]!
  STR   X2, [X4, #255]!
  STR   X2, [X4, #-256]!
  STR   X2, [X4], #0
  STR   X2, [X4], #1
  STR   X2, [X4], #255
  STR   X2, [X4], #-256

  STR   B0, [X4]
  STR   B0, [X4, #8]
  STR   B0, [X4, #7]
  STR   B0, [X4, #-5]
  STR   B0, [X4, #4095]
  STR   B0, [X4, #255]
  STR   B0, [X4, #-256]
  STR   B0, [X4, #0]!
  STR   B0, [X4, #255]!
  STR   B0, [X4, #-256]!
  STR   B0, [X4], #0
  STR   B0, [X4], #1
  STR   B0, [X4], #255
  STR   B0, [X4], #-256

  STR   H0, [X4]
  STR   H0, [X4, #8]
  STR   H0, [X4, #7]
  STR   H0, [X4, #-5]
  STR   H0, [X4, #8190]
  STR   H0, [X4, #255]
  STR   H0, [X4, #-256]
  STR   H0, [X4, #0]!
  STR   H0, [X4, #255]!
  STR   H0, [X4, #-256]!
  STR   H0, [X4], #0
  STR   H0, [X4], #1
  STR   H0, [X4], #255
  STR   H0, [X4], #-256

  STR   S0, [X4]
  STR   S0, [X4, #8]
  STR   S0, [X4, #7]
  STR   S0, [X4, #-5]
  STR   S0, [X4, #16380]
  STR   S0, [X4, #255]
  STR   S0, [X4, #-256]
  STR   S0, [X4, #0]!
  STR   S0, [X4, #255]!
  STR   S0, [X4, #-256]!
  STR   S0, [X4], #0
  STR   S0, [X4], #1
  STR   S0, [X4], #255
  STR   S0, [X4], #-256

  STR   D0, [X4]
  STR   D0, [X4, #8]
  STR   D0, [X4, #7]
  STR   D0, [X4, #-5]
  STR   D0, [X4, #32760]
  STR   D0, [X4, #255]
  STR   D0, [X4, #-256]
  STR   D0, [X4, #0]!
  STR   D0, [X4, #255]!
  STR   D0, [X4, #-256]!
  STR   D0, [X4], #0
  STR   D0, [X4], #1
  STR   D0, [X4], #255
  STR   D0, [X4], #-256

  STR   Q0, [X4]
  STR   Q0, [X4, #8]
  STR   Q0, [X4, #7]
  STR   Q0, [X4, #-5]
  STR   Q0, [X4, #65520]
  STR   Q0, [X4, #255]
  STR   Q0, [X4, #-256]
  STR   Q0, [X4, #0]!
  STR   Q0, [X4, #255]!
  STR   Q0, [X4, #-256]!
  STR   Q0, [X4], #0
  STR   Q0, [X4], #1
  STR   Q0, [X4], #255
  STR   Q0, [X4], #-256

  ADD X4, X4, #0x30
  STR   W3, [X4]
  STR   W3, [X4, #8]
  STR   W3, [X4, #7]
  STR   W3, [X4, #-5]
  STR   W3, [X4, #16380]
  STR   W3, [X4, #255]
  STR   W3, [X4, #-256]
  STR   W3, [X4, #0]!
  STR   W3, [X4, #255]!
  STR   W3, [X4, #-256]!
  STR   W3, [X4], #0
  STR   W3, [X4], #1
  STR   W3, [X4], #255
  STR   W3, [X4], #-256

  ADD X4, X4, #0x30
  STRB  W3, [X4]
  STRB  W3, [X4, #8]
  STRB  W3, [X4, #7]
  STRB  W3, [X4, #-5]
  STRB  W3, [X4, #4095]
  STRB  W3, [X4, #255]
  STRB  W3, [X4, #-256]
  STRB  W3, [X4, #0]!
  STRB  W3, [X4, #255]!
  STRB  W3, [X4, #-256]!
  STRB  W3, [X4], #0
  STRB  W3, [X4], #1
  STRB  W3, [X4], #255
  STRB  W3, [X4], #-256

  ADD X4, X4, #0x30
  STRH  W3, [X4]
  STRH  W3, [X4, #8]
  STRH  W3, [X4, #7]
  STRH  W3, [X4, #-5]
  STRH  W3, [X4, #8190]
  STRH  W3, [X4, #255]
  STRH  W3, [X4, #-256]
  STRH  W3, [X4, #0]!
  STRH  W3, [X4, #255]!
  STRH  W3, [X4, #-256]!
  STRH  W3, [X4], #0
  STRH  W3, [X4], #1
  STRH  W3, [X4], #255
  STRH  W3, [X4], #-256


  // STR {, B, H}
  ADD X5, X0, #0x800
  MOV X6, #0
  MOV X7, #0x450
  STR X2, [X5, X6]
  STR X2, [X5, X7]
  STR X2, [X5, X7, LSL #3]
  STR X2, [X5, W7, UXTW #0]
  STR X2, [X5, W7, UXTW #3]
  STR X2, [X5, W7, SXTW #0]
  STR X2, [X5, W7, SXTW #3]
  STR X2, [X5, X7, SXTX #0]
  STR X2, [X5, X7, SXTX #3]

  STR B1, [X5, X6]
  STR B1, [X5, X7]
  STR B1, [X5, X7, LSL #0]
  STR B1, [X5, W7, UXTW #0]
  STR B1, [X5, W7, SXTW #0]
  STR B1, [X5, X7, SXTX #0]

  STR H2, [X5, X6]
  STR H2, [X5, X7]
  STR H2, [X5, X7, LSL #1]
  STR H2, [X5, W7, UXTW #0]
  STR H2, [X5, W7, UXTW #1]
  STR H2, [X5, W7, SXTW #0]
  STR H2, [X5, W7, SXTW #1]
  STR H2, [X5, X7, SXTX #0]
  STR H2, [X5, X7, SXTX #1]

  STR S3, [X5, X6]
  STR S3, [X5, X7]
  STR S3, [X5, X7, LSL #2]
  STR S3, [X5, W7, UXTW #0]
  STR S3, [X5, W7, UXTW #2]
  STR S3, [X5, W7, SXTW #0]
  STR S3, [X5, W7, SXTW #2]
  STR S3, [X5, X7, SXTX #0]
  STR S3, [X5, X7, SXTX #2]

  STR D4, [X5, X6]
  STR D4, [X5, X7]
  STR D4, [X5, X7, LSL #3]
  STR D4, [X5, W7, UXTW #0]
  STR D4, [X5, W7, UXTW #3]
  STR D4, [X5, W7, SXTW #0]
  STR D4, [X5, W7, SXTW #3]
  STR D4, [X5, X7, SXTX #0]
  STR D4, [X5, X7, SXTX #3]

  STR Q0, [X5, X6]
  STR Q0, [X5, X7]
  STR Q0, [X5, X7, LSL #4]
  STR Q0, [X5, W7, UXTW #0]
  STR Q0, [X5, W7, UXTW #4]
  STR Q0, [X5, W7, SXTW #0]
  STR Q0, [X5, W7, SXTW #4]
  STR Q0, [X5, X7, SXTX #0]
  STR Q0, [X5, X7, SXTX #4]

  ADD X5, X5, #0x40
  STRB W3, [X5, X6]
  STRB W3, [X5, X7]
  STRB W3, [X5, W7, UXTW #0]
  STRB W3, [X5, W7, SXTW #0]
  STRB W3, [X5, X7, SXTX #0]

  ADD X5, X5, #0x40
  STRH W3, [X5, X6]
  STRH W3, [X5, X7]
  STRH W3, [X5, X7, LSL #1]
  STRH W3, [X5, W7, UXTW #0]
  STRH W3, [X5, W7, UXTW #1]
  STRH W3, [X5, W7, SXTW #0]
  STRH W3, [X5, W7, SXTW #1]
  STRH W3, [X5, X7, SXTX #0]
  STRH W3, [X5, X7, SXTX #1]


  // STTR {, B, H}
  ADD X6, X0, #0x790
  STTR X2, [X6]
  STTR X2, [X6, #8]
  STTR X2, [X6, #-6]
  STTR X2, [X6, #255]
  STTR X2, [X6, #-256]

  ADD X6, X6, #0x80
  STTRB W3, [X6]
  STTRB W3, [X6, #8]
  STTRB W3, [X6, #-6]
  STTRB W3, [X6, #255]
  STTRB W3, [X6, #-256]

  ADD X6, X6, #0x80
  STTRH W3, [X6]
  STTRH W3, [X6, #8]
  STTRH W3, [X6, #-6]
  STTRH W3, [X6, #255]
  STTRH W3, [X6, #-256]


  // LDP
  ADD X7, X0, #0x900
  LDP X3, X4, [X7]
  LDP X3, X4, [X7, #-16]
  LDP X3, X4, [X7, #16]
  LDP X3, X4, [X7, #-512]
  LDP X3, X4, [X7, #504]
  LDP X5, X6, [X7], #0
  LDP X5, X6, [X7], #8
  LDP X5, X6, [X7], #504
  LDP X5, X6, [X7], #-512
  LDP X2, X3, [X7, #0]!
  LDP X2, X3, [X7, #8]!
  LDP X2, X3, [X7, #504]!
  LDP X2, X3, [X7, #-512]!

  LDP W3, W4, [X7]
  LDP W3, W4, [X7, #-16]
  LDP W3, W4, [X7, #16]
  LDP W3, W4, [X7, #-256]
  LDP W3, W4, [X7, #252]
  LDP W5, W6, [X7], #0
  LDP W5, W6, [X7], #8
  LDP W5, W6, [X7], #252
  LDP W5, W6, [X7], #-256
  LDP W2, W3, [X7, #0]!
  LDP W2, W3, [X7, #8]!
  LDP W2, W3, [X7, #252]!
  LDP W2, W3, [X7, #-256]!

  LDP S0, S1, [X7]
  LDP S0, S1, [X7, #-16]
  LDP S0, S1, [X7, #16]
  LDP S0, S1, [X7, #-256]
  LDP S0, S1, [X7, #252]
  LDP S0, S1, [X7], #0
  LDP S0, S1, [X7], #8
  LDP S0, S1, [X7], #252
  LDP S0, S1, [X7], #-256
  LDP S0, S1, [X7, #0]!
  LDP S0, S1, [X7, #8]!
  LDP S0, S1, [X7, #252]!
  LDP S0, S1, [X7, #-256]!

  LDP D0, D1, [X7]
  LDP D0, D1, [X7, #-16]
  LDP D0, D1, [X7, #16]
  LDP D0, D1, [X7, #-512]
  LDP D0, D1, [X7, #504]
  LDP D0, D1, [X7], #0
  LDP D0, D1, [X7], #8
  LDP D0, D1, [X7], #504
  LDP D0, D1, [X7], #-512
  LDP D0, D1, [X7, #0]!
  LDP D0, D1, [X7, #8]!
  LDP D0, D1, [X7, #504]!
  LDP D0, D1, [X7, #-512]!

  LDP Q0, Q1, [X7]
  LDP Q0, Q1, [X7, #-16]
  LDP Q0, Q1, [X7, #16]
  LDP Q0, Q1, [X7, #-1024]
  LDP Q0, Q1, [X7, #1008]
  LDP Q0, Q1, [X7], #0
  LDP Q0, Q1, [X7], #32
  LDP Q0, Q1, [X7], #1008
  LDP Q0, Q1, [X7], #-1024
  LDP Q0, Q1, [X7, #0]!
  LDP Q0, Q1, [X7, #48]!
  LDP Q0, Q1, [X7, #1008]!
  LDP Q0, Q1, [X7, #-1024]!


  // STP
  STP X3, X4, [X7]
  STP X3, X4, [X7, #-16]
  STP X3, X4, [X7, #16]
  STP X3, X4, [X7, #-512]
  STP X3, X4, [X7, #504]
  STP X5, X6, [X7], #0
  STP X5, X6, [X7], #8
  STP X5, X6, [X7], #504
  STP X5, X6, [X7], #-512
  STP X2, X3, [X7, #0]!
  STP X2, X3, [X7, #8]!
  STP X2, X3, [X7, #504]!
  STP X2, X3, [X7, #-512]!

  STP W3, W4, [X7]
  STP W3, W4, [X7, #-16]
  STP W3, W4, [X7, #16]
  STP W3, W4, [X7, #-256]
  STP W3, W4, [X7, #252]
  STP W5, W6, [X7], #0
  STP W5, W6, [X7], #8
  STP W5, W6, [X7], #252
  STP W5, W6, [X7], #-256
  STP W2, W3, [X7, #0]!
  STP W2, W3, [X7, #8]!
  STP W2, W3, [X7, #252]!
  STP W2, W3, [X7, #-256]!

  STP S2, S3, [X7]
  STP S2, S3, [X7, #-16]
  STP S2, S3, [X7, #16]
  STP S2, S3, [X7, #-256]
  STP S2, S3, [X7, #252]
  STP S2, S3, [X7], #0
  STP S2, S3, [X7], #8
  STP S2, S3, [X7], #252
  STP S2, S3, [X7], #-256
  STP S2, S3, [X7, #0]!
  STP S2, S3, [X7, #8]!
  STP S2, S3, [X7, #252]!
  STP S2, S3, [X7, #-256]!

  STP D2, D3, [X7]
  STP D2, D3, [X7, #-16]
  STP D2, D3, [X7, #16]
  STP D2, D3, [X7, #-512]
  STP D2, D3, [X7, #504]
  STP D2, D3, [X7], #0
  STP D2, D3, [X7], #8
  STP D2, D3, [X7], #504
  STP D2, D3, [X7], #-512
  STP D2, D3, [X7, #0]!
  STP D2, D3, [X7, #8]!
  STP D2, D3, [X7, #504]!
  STP D2, D3, [X7, #-512]!

  STP Q2, Q3, [X7]
  STP Q2, Q3, [X7, #-32]
  STP Q2, Q3, [X7, #32]
  STP Q2, Q3, [X7, #-1024]
  STP Q2, Q3, [X7, #1008]
  STP Q2, Q3, [X7], #0
  STP Q2, Q3, [X7], #32
  STP Q2, Q3, [X7], #1008
  STP Q2, Q3, [X7], #-1024
  STP Q2, Q3, [X7, #0]!
  STP Q2, Q3, [X7, #32]!
  STP Q2, Q3, [X7, #1008]!
  STP Q2, Q3, [X7, #-1024]!


  // LDNP
  LDNP X3, X4, [X7]
  LDNP X3, X4, [X7, #-16]
  LDNP X3, X4, [X7, #16]
  LDNP X3, X4, [X7, #-512]
  LDNP X3, X4, [X7, #504]
  LDNP W3, W4, [X7]
  LDNP W3, W4, [X7, #-16]
  LDNP W3, W4, [X7, #16]
  LDNP W3, W4, [X7, #-256]
  LDNP W3, W4, [X7, #252]

  LDNP S0, S1, [X7]
  LDNP S0, S1, [X7, #-16]
  LDNP S0, S1, [X7, #16]
  LDNP S0, S1, [X7, #-256]
  LDNP S0, S1, [X7, #252]
  LDNP D2, D3, [X7]
  LDNP D2, D3, [X7, #-16]
  LDNP D2, D3, [X7, #16]
  LDNP D2, D3, [X7, #-512]
  LDNP D2, D3, [X7, #504]
  LDNP Q2, Q3, [X7]
  LDNP Q2, Q3, [X7, #-16]
  LDNP Q2, Q3, [X7, #16]
  LDNP Q2, Q3, [X7, #-1024]
  LDNP Q2, Q3, [X7, #1008]


  // STNP
  STNP X3, X4, [X7]
  STNP X3, X4, [X7, #-16]
  STNP X3, X4, [X7, #16]
  STNP X3, X4, [X7, #-512]
  STNP X3, X4, [X7, #504]
  STNP W3, W4, [X7]
  STNP W3, W4, [X7, #-16]
  STNP W3, W4, [X7, #16]
  STNP W3, W4, [X7, #-256]
  STNP W3, W4, [X7, #252]

  STNP S0, S1, [X7]
  STNP S0, S1, [X7, #-16]
  STNP S0, S1, [X7, #16]
  STNP S0, S1, [X7, #-256]
  STNP S0, S1, [X7, #252]
  STNP D0, D1, [X7]
  STNP D0, D1, [X7, #-16]
  STNP D0, D1, [X7, #16]
  STNP D0, D1, [X7, #-512]
  STNP D0, D1, [X7, #504]
  STNP Q0, Q1, [X7]
  STNP Q0, Q1, [X7, #-16]
  STNP Q0, Q1, [X7, #16]
  STNP Q0, Q1, [X7, #-1024]
  STNP Q0, Q1, [X7, #1008]


  // LDPSW
  LDPSW X3, X4, [X7]
  LDPSW X3, X4, [X7, #-16]
  LDPSW X3, X4, [X7, #16]
  LDPSW X3, X4, [X7, #-256]
  LDPSW X3, X4, [X7, #252]
  LDPSW X5, X6, [X7], #0
  LDPSW X5, X6, [X7], #8
  LDPSW X5, X6, [X7], #252
  LDPSW X5, X6, [X7], #-256
  LDPSW X2, X3, [X7, #0]!
  LDPSW X2, X3, [X7, #8]!
  LDPSW X2, X3, [X7, #252]!
  LDPSW X2, X3, [X7, #-256]!


  // load-acquire
  MOV X2, X0
  MOV X3, X0
  LDAR X6, [X0]
  LDARB W7, [X2]
  LDARH W2, [X3]


  // store-release
  MOV X2, X0
  MOV X3, X0
  STLR X4, [X0]
  STLRB W5, [X2]
  STLRH W6, [X3]


  // Stack accesses
  STR X3, [SP, #-32]!
  STP X4, X5, [SP, #16]
  LDP X4, X5, [SP, #16]
  LDR X3, [SP], #32

  STP X2, X3, [SP, #-32]!
  STR X4, [SP, #24]
  LDR X4, [SP, #24]
  LDP X2, X3, [SP], #32

  SUB SP, SP, #16
  STR W2, [SP, #0]
  STR W3, [SP, #4]
  STP W4, W5, [SP, #8]
  LDP W4, W5, [SP, #8]
  LDR W3, [SP, #4]
  LDR W2, [SP], #16


  // Load / store exclusive
  ADD X5, X0, #0x30
  ADD X6, X0, #0x230

  LDXP X2, X3, [X0]
  STXP W4, X2, X3, [X0]

  LDXR X2, [X5]
  STXR W4, X2, [X5]

  LDXRB W3, [X6]
  STXRB W4, W3, [X6]

  LDXRH W2, [X0]
  STXRH W4, W2, [X0]


  // Prefetch hints - should not generate exceptions or be traced
  PRFM PLDL1KEEP, [X0]
  PRFM PLDL1STRM, [X0]
  PRFM PLDL2KEEP, [X0]
  PRFM PLDL2STRM, [X0]
  PRFM PLDL3KEEP, [X0]
  PRFM PLDL3STRM, [X0]
  PRFM PLDL1KEEP, [X0, #32760]
  PRFM PLDL1STRM, [X0, #32760]
  PRFM PLDL2KEEP, [X0, #32760]
  PRFM PLDL2STRM, [X0, #32760]
  PRFM PLDL3KEEP, [X0, #32760]
  PRFM PLDL3STRM, [X0, #32760]
  PRFM PLDL1KEEP, [X0, #32760]
  PRFM PLDL1STRM, [X0, #32760]
  PRFM PLDL2KEEP, [X0, #32760]
  PRFM PLDL2STRM, [X0, #32760]
  PRFM PLDL3KEEP, [X0, #32760]
  PRFM PLDL3STRM, [X0, #32760]

  PRFM PLIL1KEEP, [X0]
  PRFM PLIL1STRM, [X0]
  PRFM PLIL2KEEP, [X0]
  PRFM PLIL2STRM, [X0]
  PRFM PLIL3KEEP, [X0]
  PRFM PLIL3STRM, [X0]
  PRFM PLIL1KEEP, [X0, #32760]
  PRFM PLIL1STRM, [X0, #32760]
  PRFM PLIL2KEEP, [X0, #32760]
  PRFM PLIL2STRM, [X0, #32760]
  PRFM PLIL3KEEP, [X0, #32760]
  PRFM PLIL3STRM, [X0, #32760]

  PRFM PSTL1KEEP, [X0]
  PRFM PSTL1STRM, [X0]
  PRFM PSTL2KEEP, [X0]
  PRFM PSTL2STRM, [X0]
  PRFM PSTL3KEEP, [X0]
  PRFM PSTL3STRM, [X0]
  PRFM PSTL1KEEP, [X0, #32760]
  PRFM PSTL1STRM, [X0, #32760]
  PRFM PSTL2KEEP, [X0, #32760]
  PRFM PSTL2STRM, [X0, #32760]
  PRFM PSTL3KEEP, [X0, #32760]
  PRFM PSTL3STRM, [X0, #32760]

  PRFM PLDL1KEEP, [X0, #1]
  PRFM PLDL1STRM, [X0, #1]
  PRFM PLDL2KEEP, [X0, #1]
  PRFM PLDL2STRM, [X0, #1]
  PRFM PLDL3KEEP, [X0, #1]
  PRFM PLDL3STRM, [X0, #1]
  PRFM PLDL1KEEP, [X0, #-256]
  PRFM PLDL1STRM, [X0, #-256]
  PRFM PLDL2KEEP, [X0, #-256]
  PRFM PLDL2STRM, [X0, #-256]
  PRFM PLDL3KEEP, [X0, #-256]
  PRFM PLDL3STRM, [X0, #-256]

  ADD X6, X0, #0x330
  PRFM PLDL1KEEP, [X0, X6]
  PRFM PLDL1KEEP, [X0, X6, LSL #3]
  PRFM PLDL1KEEP, [X0, X6, SXTX #0]
  PRFM PLDL1KEEP, [X0, X6, SXTX #3]
  PRFM PLDL1KEEP, [X0, W6, UXTW #0]
  PRFM PLDL1KEEP, [X0, W6, UXTW #3]
  PRFM PLDL1KEEP, [X0, W6, SXTW #0]
  PRFM PLDL1KEEP, [X0, W6, SXTW #3]

  PRFM PSTL1KEEP, [X0, X6]
  PRFM PSTL1KEEP, [X0, X6, LSL #3]
  PRFM PSTL1KEEP, [X0, X6, SXTX #0]
  PRFM PSTL1KEEP, [X0, X6, SXTX #3]
  PRFM PSTL1KEEP, [X0, W6, UXTW #0]
  PRFM PSTL1KEEP, [X0, W6, UXTW #3]
  PRFM PSTL1KEEP, [X0, W6, SXTW #0]
  PRFM PSTL1KEEP, [X0, W6, SXTW #3]

  PRFM PLIL1KEEP, [X0, X6]
  PRFM PLIL1KEEP, [X0, X6, LSL #3]
  PRFM PLIL1KEEP, [X0, X6, SXTX #0]
  PRFM PLIL1KEEP, [X0, X6, SXTX #3]
  PRFM PLIL1KEEP, [X0, W6, UXTW #0]
  PRFM PLIL1KEEP, [X0, W6, UXTW #3]
  PRFM PLIL1KEEP, [X0, W6, SXTW #0]
  PRFM PLIL1KEEP, [X0, W6, SXTW #3]

  PRFM PLDL1KEEP, lit_a64
  PRFM PLDL1STRM, lit_a64
  PRFM PLDL2KEEP, lit_a64
  PRFM PLDL2STRM, lit_a64
  PRFM PLDL3KEEP, lit_a64
  PRFM PLDL3STRM, lit_a64

  PRFM PLIL1KEEP, lit_a64
  PRFM PLIL1STRM, lit_a64
  PRFM PLIL2KEEP, lit_a64
  PRFM PLIL2STRM, lit_a64
  PRFM PLIL3KEEP, lit_a64
  PRFM PLIL3STRM, lit_a64

  PRFM PSTL1KEEP, lit_a64
  PRFM PSTL1STRM, lit_a64
  PRFM PSTL2KEEP, lit_a64
  PRFM PSTL2STRM, lit_a64
  PRFM PSTL3KEEP, lit_a64
  PRFM PSTL3STRM, lit_a64


  // ADVSIMD LD1
  ADD X5, X0, #0x500
  LD1 {v0.8b}, [X5]
  LD1 {v0.8b}, [X5], #8
  LD1 {v0.16b}, [X5]
  LD1 {v0.16b}, [X5], #16
  LD1 {v0.4h}, [X5]
  LD1 {v0.4h}, [X5], #8
  LD1 {v0.8h}, [X5]
  LD1 {v0.8h}, [X5], #16
  LD1 {v0.2s}, [X5]
  LD1 {v0.2s}, [X5], #8
  LD1 {v0.4s}, [X5]
  LD1 {v0.4s}, [X5], #16
  LD1 {v0.1d}, [X5]
  LD1 {v0.1d}, [X5], #8
  LD1 {v0.2d}, [X5]
  LD1 {v0.2d}, [X5], #16

  MOV X1, #16
  LD1 {v0.b}[1], [X0]
  LD1 {v0.b}[1], [X0], #1
  LD1 {v0.b}[1], [X0], X1
  LD1 {v2.h}[2], [X0]
  LD1 {v2.h}[2], [X0], #2
  LD1 {v2.h}[2], [X0], X1
  LD1 {v2.s}[2], [X0]
  LD1 {v2.s}[2], [X0], #4
  LD1 {v2.s}[2], [X0], X1
  LD1 {v2.d}[1], [X0]
  LD1 {v2.d}[1], [X0], #8
  LD1 {v2.d}[1], [X0], X1

  MOV X1, #32
  LD1R {v1.8b}, [X0]
  LD1R {v1.8b}, [X0], #1
  LD1R {v1.8b}, [X0], X1
  LD1R {v1.16b}, [X0]
  LD1R {v1.16b}, [X0], #1
  LD1R {v1.16b}, [X0], X1
  LD1R {v1.4h}, [X0]
  LD1R {v1.4h}, [X0], #2
  LD1R {v1.4h}, [X0], X1
  LD1R {v1.8h}, [X0]
  LD1R {v1.8h}, [X0], #2
  LD1R {v1.8h}, [X0], X1
  LD1R {v1.2s}, [X0]
  LD1R {v1.2s}, [X0], #4
  LD1R {v1.2s}, [X0], X1
  LD1R {v1.4s}, [X0]
  LD1R {v1.4s}, [X0], #4
  LD1R {v1.4s}, [X0], X1
  LD1R {v1.1d}, [X0]
  LD1R {v1.1d}, [X0], #8
  LD1R {v1.1d}, [X0], X1
  LD1R {v1.2d}, [X0]
  LD1R {v1.2d}, [X0], #8
  LD1R {v1.2d}, [X0], X1


  // ADVSIMD LD2
  ADD X6, X0, #0x200
  LD2 {v0.8b-v1.8b}, [X6]
  LD2 {v0.8b-v1.8b}, [X6], #16
  LD2 {v0.16b-v1.16b}, [X6]
  LD2 {v0.16b-v1.16b}, [X6], #32
  LD2 {v0.4h-v1.4h}, [X6]
  LD2 {v0.4h-v1.4h}, [X6], #16
  LD2 {v0.8h-v1.8h}, [X6]
  LD2 {v0.8h-v1.8h}, [X6], #32
  LD2 {v0.2s-v1.2s}, [X6]
  LD2 {v0.2s-v1.2s}, [X6], #16
  LD2 {v0.4s-v1.4s}, [X6]
  LD2 {v0.4s-v1.4s}, [X6], #32
  LD2 {v0.2d-v1.2d}, [X6]
  LD2 {v0.2d-v1.2d}, [X6], #32

  MOV X1, #64
  LD2 {v0.b-v1.b}[1], [X0]
  LD2 {v0.b-v1.b}[1], [X0], #2
  LD2 {v0.b-v1.b}[1], [X0], X1
  LD2 {v2.h-v3.h}[2], [X0]
  LD2 {v2.h-v3.h}[2], [X0], #4
  LD2 {v2.h-v3.h}[2], [X0], X1
  LD2 {v2.s-v3.s}[2], [X0]
  LD2 {v2.s-v3.s}[2], [X0], #8
  LD2 {v2.s-v3.s}[2], [X0], X1
  LD2 {v2.d-v3.d}[1], [X0]
  LD2 {v2.d-v3.d}[1], [X0], #16
  LD2 {v2.d-v3.d}[1], [X0], X1

  MOV X1, #96
  LD2R {v1.8b-v2.8b}, [X0]
  LD2R {v1.8b-v2.8b}, [X0], #2
  LD2R {v1.8b-v2.8b}, [X0], X1
  LD2R {v1.16b-v2.16b}, [X0]
  LD2R {v1.16b-v2.16b}, [X0], #2
  LD2R {v1.16b-v2.16b}, [X0], X1
  LD2R {v1.4h-v2.4h}, [X0]
  LD2R {v1.4h-v2.4h}, [X0], #4
  LD2R {v1.4h-v2.4h}, [X0], X1
  LD2R {v1.8h-v2.8h}, [X0]
  LD2R {v1.8h-v2.8h}, [X0], #4
  LD2R {v1.8h-v2.8h}, [X0], X1
  LD2R {v1.2s-v2.2s}, [X0]
  LD2R {v1.2s-v2.2s}, [X0], #8
  LD2R {v1.2s-v2.2s}, [X0], X1
  LD2R {v1.4s-v2.4s}, [X0]
  LD2R {v1.4s-v2.4s}, [X0], #8
  LD2R {v1.4s-v2.4s}, [X0], X1
  LD2R {v1.1d-v2.1d}, [X0]
  LD2R {v1.1d-v2.1d}, [X0], #16
  LD2R {v1.1d-v2.1d}, [X0], X1
  LD2R {v1.2d-v2.2d}, [X0]
  LD2R {v1.2d-v2.2d}, [X0], #16
  LD2R {v1.2d-v2.2d}, [X0], X1


  // ADVSIMD LD3
  ADD X6, X0, #0x200
  LD3 {v0.8b-v2.8b}, [X6]
  LD3 {v0.8b-v2.8b}, [X6], #24
  LD3 {v0.16b-v2.16b}, [X6]
  LD3 {v0.16b-v2.16b}, [X6], #48
  LD3 {v0.4h-v2.4h}, [X6]
  LD3 {v0.4h-v2.4h}, [X6], #24
  LD3 {v0.8h-v2.8h}, [X6]
  LD3 {v0.8h-v2.8h}, [X6], #48
  LD3 {v0.2s-v2.2s}, [X6]
  LD3 {v0.2s-v2.2s}, [X6], #24
  LD3 {v0.4s-v2.4s}, [X6]
  LD3 {v0.4s-v2.4s}, [X6], #48
  LD3 {v0.2d-v2.2d}, [X6]
  LD3 {v0.2d-v2.2d}, [X6], #48

  MOV X1, #64
  LD3 {v0.b-v2.b}[1], [X0]
  LD3 {v0.b-v2.b}[1], [X0], #3
  LD3 {v0.b-v2.b}[1], [X0], X1
  LD3 {v2.h-v4.h}[2], [X0]
  LD3 {v2.h-v4.h}[2], [X0], #6
  LD3 {v2.h-v4.h}[2], [X0], X1
  LD3 {v2.s-v4.s}[2], [X0]
  LD3 {v2.s-v4.s}[2], [X0], #12
  LD3 {v2.s-v4.s}[2], [X0], X1
  LD3 {v2.d-v4.d}[1], [X0]
  LD3 {v2.d-v4.d}[1], [X0], #24
  LD3 {v2.d-v4.d}[1], [X0], X1

  MOV X1, #96
  LD3R {v1.8b-v3.8b}, [X0]
  LD3R {v1.8b-v3.8b}, [X0], #3
  LD3R {v1.8b-v3.8b}, [X0], X1
  LD3R {v1.16b-v3.16b}, [X0]
  LD3R {v1.16b-v3.16b}, [X0], #3
  LD3R {v1.16b-v3.16b}, [X0], X1
  LD3R {v1.4h-v3.4h}, [X0]
  LD3R {v1.4h-v3.4h}, [X0], #6
  LD3R {v1.4h-v3.4h}, [X0], X1
  LD3R {v1.8h-v3.8h}, [X0]
  LD3R {v1.8h-v3.8h}, [X0], #6
  LD3R {v1.8h-v3.8h}, [X0], X1
  LD3R {v1.2s-v3.2s}, [X0]
  LD3R {v1.2s-v3.2s}, [X0], #12
  LD3R {v1.2s-v3.2s}, [X0], X1
  LD3R {v1.4s-v3.4s}, [X0]
  LD3R {v1.4s-v3.4s}, [X0], #12
  LD3R {v1.4s-v3.4s}, [X0], X1
  LD3R {v1.1d-v3.1d}, [X0]
  LD3R {v1.1d-v3.1d}, [X0], #24
  LD3R {v1.1d-v3.1d}, [X0], X1
  LD3R {v1.2d-v3.2d}, [X0]
  LD3R {v1.2d-v3.2d}, [X0], #24
  LD3R {v1.2d-v3.2d}, [X0], X1


  // ADVSIMD LD4
  ADD X6, X0, #0x200
  LD4 {v0.8b-v3.8b}, [X6]
  LD4 {v0.8b-v3.8b}, [X6], #32
  LD4 {v0.16b-v3.16b}, [X6]
  LD4 {v0.16b-v3.16b}, [X6], #64
  LD4 {v0.4h-v3.4h}, [X6]
  LD4 {v0.4h-v3.4h}, [X6], #32
  LD4 {v0.8h-v3.8h}, [X6]
  LD4 {v0.8h-v3.8h}, [X6], #64
  LD4 {v0.2s-v3.2s}, [X6]
  LD4 {v0.2s-v3.2s}, [X6], #32
  LD4 {v0.4s-v3.4s}, [X6]
  LD4 {v0.4s-v3.4s}, [X6], #64
  LD4 {v0.2d-v3.2d}, [X6]
  LD4 {v0.2d-v3.2d}, [X6], #64

  MOV X1, #64
  LD4 {v0.b-v3.b}[1], [X0]
  LD4 {v0.b-v3.b}[1], [X0], #4
  LD4 {v0.b-v3.b}[1], [X0], X1
  LD4 {v2.h-v5.h}[2], [X0]
  LD4 {v2.h-v5.h}[2], [X0], #8
  LD4 {v2.h-v5.h}[2], [X0], X1
  LD4 {v2.s-v5.s}[2], [X0]
  LD4 {v2.s-v5.s}[2], [X0], #16
  LD4 {v2.s-v5.s}[2], [X0], X1
  LD4 {v2.d-v5.d}[1], [X0]
  LD4 {v2.d-v5.d}[1], [X0], #32
  LD4 {v2.d-v5.d}[1], [X0], X1

  MOV X1, #96
  LD4R {v1.8b-v4.8b}, [X0]
  LD4R {v1.8b-v4.8b}, [X0], #4
  LD4R {v1.8b-v4.8b}, [X0], X1
  LD4R {v1.16b-v4.16b}, [X0]
  LD4R {v1.16b-v4.16b}, [X0], #4
  LD4R {v1.16b-v4.16b}, [X0], X1
  LD4R {v1.4h-v4.4h}, [X0]
  LD4R {v1.4h-v4.4h}, [X0], #8
  LD4R {v1.4h-v4.4h}, [X0], X1
  LD4R {v1.8h-v4.8h}, [X0]
  LD4R {v1.8h-v4.8h}, [X0], #8
  LD4R {v1.8h-v4.8h}, [X0], X1
  LD4R {v1.2s-v4.2s}, [X0]
  LD4R {v1.2s-v4.2s}, [X0], #16
  LD4R {v1.2s-v4.2s}, [X0], X1
  LD4R {v1.4s-v4.4s}, [X0]
  LD4R {v1.4s-v4.4s}, [X0], #16
  LD4R {v1.4s-v4.4s}, [X0], X1
  LD4R {v1.1d-v4.1d}, [X0]
  LD4R {v1.1d-v4.1d}, [X0], #32
  LD4R {v1.1d-v4.1d}, [X0], X1
  LD4R {v1.2d-v4.2d}, [X0]
  LD4R {v1.2d-v4.2d}, [X0], #32
  LD4R {v1.2d-v4.2d}, [X0], X1


  // ADVSIMD ST1
  ADD X5, X0, #0xd00
  ST1 {v0.8b}, [X5]
  ST1 {v0.8b}, [X5], #8
  ST1 {v0.16b}, [X5]
  ST1 {v0.16b}, [X5], #16
  ST1 {v0.4h}, [X5]
  ST1 {v0.4h}, [X5], #8
  ST1 {v0.8h}, [X5]
  ST1 {v0.8h}, [X5], #16
  ST1 {v0.2s}, [X5]
  ST1 {v0.2s}, [X5], #8
  ST1 {v0.4s}, [X5]
  ST1 {v0.4s}, [X5], #16
  ST1 {v0.1d}, [X5]
  ST1 {v0.1d}, [X5], #8
  ST1 {v0.2d}, [X5]
  ST1 {v0.2d}, [X5], #16

  MOV X1, #16
  ST1 {v0.b}[1], [X0]
  ST1 {v0.b}[1], [X0], #1
  ST1 {v0.b}[1], [X0], X1
  ST1 {v2.h}[2], [X0]
  ST1 {v2.h}[2], [X0], #2
  ST1 {v2.h}[2], [X0], X1
  ST1 {v2.s}[2], [X0]
  ST1 {v2.s}[2], [X0], #4
  ST1 {v2.s}[2], [X0], X1
  ST1 {v2.d}[1], [X0]
  ST1 {v2.d}[1], [X0], #8
  ST1 {v2.d}[1], [X0], X1


  // ADVSIMD ST2
  ADD X6, X0, #0x200
  ST2 {v0.8b-v1.8b}, [X6]
  ST2 {v0.8b-v1.8b}, [X6], #16
  ST2 {v0.16b-v1.16b}, [X6]
  ST2 {v0.16b-v1.16b}, [X6], #32
  ST2 {v0.4h-v1.4h}, [X6]
  ST2 {v0.4h-v1.4h}, [X6], #16
  ST2 {v0.8h-v1.8h}, [X6]
  ST2 {v0.8h-v1.8h}, [X6], #32
  ST2 {v0.2s-v1.2s}, [X6]
  ST2 {v0.2s-v1.2s}, [X6], #16
  ST2 {v0.4s-v1.4s}, [X6]
  ST2 {v0.4s-v1.4s}, [X6], #32
  ST2 {v0.2d-v1.2d}, [X6]
  ST2 {v0.2d-v1.2d}, [X6], #32

  MOV X1, #64
  ST2 {v0.b-v1.b}[1], [X0]
  ST2 {v0.b-v1.b}[1], [X0], #2
  ST2 {v0.b-v1.b}[1], [X0], X1
  ST2 {v2.h-v3.h}[2], [X0]
  ST2 {v2.h-v3.h}[2], [X0], #4
  ST2 {v2.h-v3.h}[2], [X0], X1
  ST2 {v2.s-v3.s}[2], [X0]
  ST2 {v2.s-v3.s}[2], [X0], #8
  ST2 {v2.s-v3.s}[2], [X0], X1
  ST2 {v2.d-v3.d}[1], [X0]
  ST2 {v2.d-v3.d}[1], [X0], #16
  ST2 {v2.d-v3.d}[1], [X0], X1


  // ADVSIMD ST3
  ADD X6, X0, #0x200
  ST3 {v0.8b-v2.8b}, [X6]
  ST3 {v0.8b-v2.8b}, [X6], #24
  ST3 {v0.16b-v2.16b}, [X6]
  ST3 {v0.16b-v2.16b}, [X6], #48
  ST3 {v0.4h-v2.4h}, [X6]
  ST3 {v0.4h-v2.4h}, [X6], #24
  ST3 {v0.8h-v2.8h}, [X6]
  ST3 {v0.8h-v2.8h}, [X6], #48
  ST3 {v0.2s-v2.2s}, [X6]
  ST3 {v0.2s-v2.2s}, [X6], #24
  ST3 {v0.4s-v2.4s}, [X6]
  ST3 {v0.4s-v2.4s}, [X6], #48
  ST3 {v0.2d-v2.2d}, [X6]
  ST3 {v0.2d-v2.2d}, [X6], #48

  MOV X1, #64
  ST3 {v0.b-v2.b}[1], [X0]
  ST3 {v0.b-v2.b}[1], [X0], #3
  ST3 {v0.b-v2.b}[1], [X0], X1
  ST3 {v2.h-v4.h}[2], [X0]
  ST3 {v2.h-v4.h}[2], [X0], #6
  ST3 {v2.h-v4.h}[2], [X0], X1
  ST3 {v2.s-v4.s}[2], [X0]
  ST3 {v2.s-v4.s}[2], [X0], #12
  ST3 {v2.s-v4.s}[2], [X0], X1
  ST3 {v2.d-v4.d}[1], [X0]
  ST3 {v2.d-v4.d}[1], [X0], #24
  ST3 {v2.d-v4.d}[1], [X0], X1


  // ADVSIMD ST4
  ADD X6, X0, #0x200
  ST4 {v0.8b-v3.8b}, [X6]
  ST4 {v0.8b-v3.8b}, [X6], #32
  ST4 {v0.16b-v3.16b}, [X6]
  ST4 {v0.16b-v3.16b}, [X6], #64
  ST4 {v0.4h-v3.4h}, [X6]
  ST4 {v0.4h-v3.4h}, [X6], #32
  ST4 {v0.8h-v3.8h}, [X6]
  ST4 {v0.8h-v3.8h}, [X6], #64
  ST4 {v0.2s-v3.2s}, [X6]
  ST4 {v0.2s-v3.2s}, [X6], #32
  ST4 {v0.4s-v3.4s}, [X6]
  ST4 {v0.4s-v3.4s}, [X6], #64
  ST4 {v0.2d-v3.2d}, [X6]
  ST4 {v0.2d-v3.2d}, [X6], #64

  MOV X1, #64
  ST4 {v0.b-v3.b}[1], [X0]
  ST4 {v0.b-v3.b}[1], [X0], #4
  ST4 {v0.b-v3.b}[1], [X0], X1
  ST4 {v2.h-v5.h}[2], [X0]
  ST4 {v2.h-v5.h}[2], [X0], #8
  ST4 {v2.h-v5.h}[2], [X0], X1
  ST4 {v2.s-v5.s}[2], [X0]
  ST4 {v2.s-v5.s}[2], [X0], #16
  ST4 {v2.s-v5.s}[2], [X0], X1
  ST4 {v2.d-v5.d}[1], [X0]
  ST4 {v2.d-v5.d}[1], [X0], #32
  ST4 {v2.d-v5.d}[1], [X0], X1


  // Literal loads - not trapped
  LDR   X2, lit_a64
  LDR   W3, lit_a64
  LDRSW X2, lit_a64
  LDR   S0, lit_a64
  LDR   D1, lit_a64
  LDR   Q2, lit_a64


  MOV SP, X29
  RET

lit_a64: .quad 0

.endfunc

.global end_test_a64
end_test_a64:
#endif
