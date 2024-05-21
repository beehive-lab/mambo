=begin

This file is part of PIE, an instruction encoder / decoder generator:
    https://github.com/beehive-lab/pie

Copyright 2011-2016 Cosmin Gorgovan <cosmin at linux-geek dot org>
Copyright 2017-2021 The University of Manchester

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

=end

require './generate_common.rb'

def generate_f_prot(inst, inst_len)
  prot = "void #{ARGV[0]}_#{inst[:name]}_decode_fields"
  prot += " (\n"
  prot += "\t#{inst_len_to_cptr(inst_len)} *address"

  inst[:fields].each_pair do |field_label, field|
    next if field[:name] == "auto_cond"
    prot += ",\n\tunsigned int *#{field[:name]}"
  end

  prot += ")"

  return prot
end

def generate_f_body(inst, def_inst_len, swaphw)
  body =  "\n{\n"

  if (inst[:bitmap].size == def_inst_len)
    body += "\t#{inst_len_to_cptr(inst[:bitmap].size)} instruction = *address;\n"
  elsif (inst[:bitmap].size == def_inst_len * 2)
    if (swaphw)
      body += "\t#{inst_len_to_cptr(inst[:bitmap].size)} instruction = (*(address + 1) << #{def_inst_len}) | *address;\n"
    else
      body += "\t#{inst_len_to_cptr(inst[:bitmap].size)} instruction = (*address << #{def_inst_len}) | *(address + 1);\n"
    end
  else
    abort "Unknown instruction inst word length"
  end

  inst[:fields].each_pair do |label, field|
    next if field[:name] == "auto_cond"
    shift = get_field_shift(inst[:bitmap], label)
    mask = get_field_mask(inst[:bitmap], label)
    body += "\t*#{field[:name]} = (instruction >> #{shift}) & #{mask};\n"
  end

  body +=  "}"

  return body
end

def generate_field_decoder(insts, inst_len, is_header, swaphw)
  insts.each do |inst|
    # skip instructions with no arguments
    next if inst[:fields].size == 0 or (inst[:fields].size == 1 && inst[:fields].first[1][:name] == "auto_cond")
    print generate_f_prot(inst, inst_len)
    puts ";" if is_header
    puts generate_f_body(inst, inst_len, swaphw) unless is_header
  end
end

def generate_header(insts, inst_len)
  puts "#ifndef __#{ARGV[0].upcase}_PIE_FIELD_DECODER_H__"
  puts "#define __#{ARGV[0].upcase}_PIE_FIELD_DECODER_H__"
  puts "#include <stdint.h>"

  generate_field_decoder(insts, inst_len, true, false)

  puts "#endif"
end

def generate_all(insts, inst_len, swaphw)
  puts "#include \"pie-#{ARGV[0]}-field-decoder.h\""

  generate_field_decoder(insts, inst_len, false, swaphw)
end

is_header = ARGV[1...ARGV.size].include?("header")
swaphw = ARGV[1...ARGV.size].include?("swaphw")

insts = process_all(ARGV[0] + ".txt", false)
inst_len = get_min_inst_len(insts)
if (is_header)
  generate_header(insts, inst_len)
else
  generate_all(insts, inst_len, swaphw)
end
