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

class Node
  attr_accessor :depth, :instruction, :left, :right
  @depth
  @value
  @left
  @right
end

def generate_f_prot(insts, c_ptr)
  print "#{ARGV[0]}_instruction #{ARGV[0]}_decode(#{c_ptr} *address)"
end

def generate_header(insts, inst_len)
  puts "#ifndef __#{ARGV[0].upcase}_PIE_DECODER_H__"
  puts "#define  __#{ARGV[0].upcase}_PIE_DECODER_H__"
  puts "#include <stdint.h>"
  puts "typedef enum {"
  insts.each do |inst|
    puts "  #{ARGV[0].upcase}_#{inst[:name].upcase},"
  end
  puts "  #{ARGV[0].upcase}_INVALID"  
  puts "} #{ARGV[0]}_instruction;"
  generate_f_prot(insts, inst_len_to_cptr(inst_len))
  puts ";"
  puts "#endif"
end

def select_bit(instructions, allowed_bits)
  bit = 0
  selected_bit = -1
  selected_bit_count = 0

  while (allowed_bits > 0)
    cur_bit_mask = (0x80000000 >> bit)

    if ((allowed_bits & cur_bit_mask) != 0)
      count = 0
      instructions.each do |instruction|
        set_bits = instruction[:bitmask_set_bits]
        count += 1 if ((set_bits & cur_bit_mask) != 0)
      end
      if (count > selected_bit_count)
        selected_bit = bit
        selected_bit_count = count
      end
    end

    allowed_bits &= ~cur_bit_mask
    bit += 1
  end

  return selected_bit
end

def build_tree(instructions, remaining_bits, var_inst_len)
  if (instructions.size == 0)
    return nil
  end

  if (instructions.size == 1 and ((instructions[0][:bitmask_set_bits] & remaining_bits) == 0))
    node = Node.new
    node.instruction = instructions[0]
    return node
  end

  progress = false
  bit = -1
  if (var_inst_len)
    if ((remaining_bits & 0xFFFF0000) != 0)
      bit = select_bit(instructions, remaining_bits & 0xFFFF0000)
    end

    if bit < 0
      bit = select_bit(instructions, remaining_bits & 0xFFFF)
    end
  else
    bit = select_bit(instructions, remaining_bits)
  end

  if (bit >= 0)
    left = []
    right = []
  
    instructions.each do |instruction|
      if (instruction[:bitmap][bit] == '0')
        left.push(instruction)
        progress = true
      elsif (instruction[:bitmap][bit] == '1')
        right.push(instruction)
        progress = true
      elsif (instruction[:bitmap][bit].match(/[a-z]/))
        left.push(instruction)
        right.push(instruction)
      else
        warn max_word_length
        warn instructions.inspect
        abort "Unknown bit value in bit #{bit} in " + instruction[:bitmap] + " in " + instruction[:name]
      end
    end
  end
  
  node = Node.new
  node.depth = bit

  #terminate after scanning the whole instruction word
  unless (progress)
    most_specific = 0
    i = nil
    instructions.each do |instruction|
      count = instruction[:bitmap].count("01")
      if count > most_specific
        most_specific = count
        i = instruction
      end
    end

    node.instruction = i
    return node
  end

  remaining_bits &= ~(0x80000000 >> bit)
  node.left =  build_tree(left, remaining_bits, var_inst_len)
  node.right = build_tree(right, remaining_bits, var_inst_len)
  return node
end

def indent(depth)
 (0..depth).each do |i|
    print "  "
  end
end

def generate_c(node, depth, def_inst_width, sub)
  indent(depth)
  if (node == nil)
    puts "return #{ARGV[0].upcase}_INVALID;"
    return
  end
  if (node.instruction)
    puts "// #{node.instruction[:bitmap].gsub(/[a-z]/, 'x')}"
    indent(depth)
    puts "return #{ARGV[0].upcase}_#{node.instruction[:name].to_s.upcase};"
    return
  end
  
  if ((node.depth - sub) >= def_inst_width)
    puts "instruction = *(++address);"
    sub += def_inst_width
    indent(depth)
  end
  puts "if ((instruction & (1 << #{(def_inst_width - (node.depth - sub) -1)})) == 0) {"
  generate_c(node.left, depth+1, def_inst_width, sub)
  indent(depth)
  puts "} else {"
  generate_c(node.right, depth+1, def_inst_width, sub)
  indent(depth)
  puts "}"
end

def get_field_width(inst, field_label)
  return inst[:bitmap].count(field_label)
end

def inst_set_field(inst, field_label, field_width, val)
  index = -1
  while (index = inst[:bitmap].index(field_label, index + 1))
    field_width -= 1
    inst[:bitmap][index] = ((val >> field_width) & 1).to_s(2);
  end
end

def handle_cond_field(inst)
  insts = []
  return insts unless inst[:fields]

  inst[:fields].each do |field_label, field|
    if field[:cond]
      field_width = get_field_width(inst, field_label)
      (0...(1 << field_width)).each do |value|
        is_valid = false
        if field[:cond] == :diff && !field[:cond_vals].include?(value)
          is_valid = true
        end
        if field[:cond] == :eq && field[:cond_vals].include?(value)
          is_valid = true
        end

        if is_valid
          new_inst = inst.dup
          new_inst[:bitmap] = inst[:bitmap].dup
          new_inst[:fields] = new_inst[:fields].dup
          new_inst[:fields].each do |fl, f|
            new_inst[:fields][fl] = new_inst[:fields][fl].dup
          end
          new_inst[:fields][field_label].delete(:cond)
          new_inst[:fields][field_label].delete(:cond_vals)
          inst_set_field(new_inst, field_label, field_width, value)
          insts.push(new_inst)
        end
      end
      break
    end
  end

  results = []
  insts.each do |new_inst|
    t_insts = handle_cond_field(new_inst)
    if t_insts.size > 0
      results.concat(t_insts)
    else
      results.push(new_inst)
    end
  end

  return results
end

def generate_decoder(raw_insts, inst_len)
  max_word_length = get_max_inst_len(raw_insts)
  if (inst_len != max_word_length && inst_len*2 != max_word_length)
    abort "Unsupported configuration (#{inst_len}, #{max_word_length})"
  end
  var_inst_len = (inst_len != max_word_length)

  insts = []
  raw_insts.each do |inst|
    new_insts = handle_cond_field(inst)
    if new_insts.size > 0
      insts.concat(new_insts)
    else
      insts.push(inst)
    end
  end

  insts.each do |inst|
    inst[:bitmask_set_bits] = inst[:bitmap].gsub('0','1').gsub(/[a-z]/, '0').to_i(2)
    inst[:bitmask_value] = inst[:bitmap].gsub(/[a-z]/, '0').to_i(2)

    if (inst[:bitmap].size < max_word_length)
      inst[:bitmask_set_bits] = inst[:bitmask_set_bits] << inst_len
      inst[:bitmask_value] = inst[:bitmask_set_bits] << inst_len
    end
  end

  c_ptr = inst_len_to_cptr(inst_len)
  puts "#include \"pie-#{ARGV[0]}-decoder.h\"\n\n"
  generate_f_prot(insts, c_ptr)
  puts " {"
  puts "  #{c_ptr} instruction = *address;"
  tree = build_tree(insts, (1 << max_word_length) - 1, var_inst_len)
  generate_c(tree, 0, inst_len, 0)
  puts "}"
end

is_header = ARGV[1...ARGV.size].include?("header")
swaphw = ARGV[1...ARGV.size].include?("swaphw")

insts = process_insts(ARGV[0] + ".txt", swaphw)

inst_len = get_min_inst_len(insts)

if (is_header)
  generate_header(insts, inst_len)
else
  generate_decoder(insts, inst_len)
end

