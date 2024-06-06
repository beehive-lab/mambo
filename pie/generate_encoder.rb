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

def has_cond_field(inst)
  inst[:fields].each_pair do |field_label, field|
    return true if field[:name] == "auto_cond"
  end
  return false
end

def generate_f_prot(inst, inst_len, cond)
  prot = "void #{ARGV[0]}_#{inst[:name]}"
  prot += "_cond" if has_cond_field(inst) and cond
  prot += " (\n"
  prot += "\t#{inst_len_to_cptr(inst_len)} **address"

  inst[:fields].each_pair do |field_label, field|
    prot += ",\n\tunsigned int #{field[:name]}" unless (field[:name] == "auto_cond" && !cond)
  end

  prot += "\n)"

  return prot
end

def generate_f_body(inst, def_inst_len, cond, swaphw)
  body =  "{\n"
  body += "\t// #{inst[:bitmap]}\n"
  body +=  "\t#{inst_len_to_cptr(inst[:bitmap].size)} inst = 0x"

  fixed_fields = inst[:bitmap].gsub(/[a-z]/, '0').to_i(2).to_s(16)
  body += fixed_fields

  inst[:fields].each_pair do |label, field|
    if field[:name] == "auto_cond" and !cond
      body += " | (14 << #{get_field_shift(inst[:bitmap], label)})"
    else
      body += " | ((#{field[:name]} & #{get_field_mask(inst[:bitmap], label)}) << #{get_field_shift(inst[:bitmap], label)})"
    end
  end

  body += ";\n\t"
  if (inst[:bitmap].size == def_inst_len)
    body += "**address = inst;\n"
  elsif (inst[:bitmap].size == def_inst_len*2)
    body += "*(*address#{swaphw ? ' + 1' : ''}) = (#{inst_len_to_cptr(def_inst_len)})(inst >> #{def_inst_len});\n"
    bitmask = ((1 << def_inst_len) - 1).to_s(16)
    body += "\t*(*address#{swaphw ? '' : ' + 1'}) = (#{inst_len_to_cptr(def_inst_len)})(inst & 0x#{bitmask});\n"
  else
    abort "Unknown instruction inst word length"
  end

  body +=  "}"

  return body
end

def generate_encoder(insts, inst_len, is_header, swaphw)
  insts.each do |inst|
    if has_cond_field(inst)
      print generate_f_prot(inst, inst_len, true)
      puts ";" if is_header
      puts generate_f_body(inst, inst_len, true, swaphw) unless is_header
    end
    print generate_f_prot(inst, inst_len, false)
    puts ";" if is_header
    puts generate_f_body(inst, inst_len, false, swaphw) unless is_header
  end
end

def generate_header(insts, inst_len)
  puts "#ifndef __#{ARGV[0].upcase}_PIE_ENCODER_H__"
  puts "#define __#{ARGV[0].upcase}_PIE_ENCODER_H__"
  puts "#include <stdint.h>"

  generate_encoder(insts, inst_len, true, false)

  puts "#endif"
end

def generate_all(insts, inst_len, swaphw)
  puts "#include \"pie-#{ARGV[0]}-encoder.h\""

  generate_encoder(insts, inst_len, false, swaphw)
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
