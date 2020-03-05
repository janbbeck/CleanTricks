from binaryninja import *
from operator import itemgetter
import time

def clean_tricks_template(bv):
         # empty template to play with
         start = time.time()
         instructionList = sorted(bv.instructions, key=itemgetter(1)) # sort instructions by address. BN does not provide this in order. Also, there are duplicates...
         # or instructionList = bv.instructions   , because sometimes listing by block is more useful
         last_instruction = None    # keep track of the instructions before the one under current consideration
         last_instruction2 = None   # keep track of the instructions before the one under current consideration
         for instruction in instructionList:
            # add processing here
            last_instruction2 = last_instruction    # keep track of the instructions before the one under current consideration
            last_instruction = instruction          # keep track of the instructions before the one under current consideration
         end = time.time()
         binaryninja.log_info(repr(end-start))
         binaryninja.log_info("Done. Finished in {} seconds.".format(end-start))

def clean_tricks_push_xor_je_pop(bv):
         #push REG, xor REG,REG, je, pop REG
         start = time.time()
         patchCount = 0
         instructionList = sorted(bv.instructions, key=itemgetter(1)) # sort instructions by address. BN does not provide this in order
         last_instruction = None
         last_instruction2 = None
         last_instruction3 = None
         last_instruction4 = None
         for instruction in instructionList:
            if last_instruction2 is not None:  
               if repr(instruction) == repr(last_instruction):  # ignore repeated/duplicate code blocks
                   continue
               if repr(instruction) == repr(last_instruction2): # ignore repeated/duplicate code blocks
                   continue
               if "'push'" in repr(last_instruction2): 
                if "'xor'" in repr(last_instruction):   
                 if "je" in repr(instruction):   
                    if repr(last_instruction[0][2]) == repr(last_instruction[0][4]):      # xor has to happen on single register     
                     if repr(last_instruction[0][2]) == repr(last_instruction2[0][2]):    # push xor registers have to match  
                        target_address = int(repr(instruction[0][2]).strip("'"),16)       # the target of the je instruction 
                        target_instruction = bv.get_disassembly(target_address)  
                        if "pop" in target_instruction:                                   # has to be a pop instruction   
                           if repr(last_instruction2[0][2]).strip("'") in target_instruction:      # push and pop registers have to match   
                               binaryninja.log_info(repr(last_instruction2))   
                               binaryninja.log_info(repr(last_instruction))   
                               binaryninja.log_info(repr(instruction)) 
                               binaryninja.log_info(repr(bv.get_disassembly(target_address)))  
                               patchCount = patchCount + 1         
                               bv.convert_to_nop(last_instruction2[1])
                               bv.convert_to_nop(last_instruction[1])
                               bv.always_branch(instruction[1]) # jump always
                               bv.convert_to_nop(target_address)
            last_instruction4 = last_instruction3
            last_instruction3 = last_instruction2
            last_instruction2 = last_instruction
            last_instruction = instruction
         end = time.time()
         binaryninja.log_info(repr(end-start))
         binaryninja.log_info("Done. Finished in {} seconds.".format(end-start))
         binaryninja.log_info("{} patches performed.".format(patchCount))

def clean_tricks_jmp_inc_dec(bv):
         # jmp (overlaps inc instruction) -> inc REG -> dec REG
         start = time.time()
         patchCount = 0
         instructionList = sorted(bv.instructions, key=itemgetter(1)) # sort instructions by address. BN does not provide this in order
         last_instruction = None
         last_instruction2 = None
         for instruction in instructionList:
            if last_instruction2 is not None:
               if repr(instruction[0]) == repr(last_instruction[0]):  # ignore repeated/duplicate code blocks
                   continue
               if repr(instruction[0]) == repr(last_instruction2[0]): # ignore repeated/duplicate code blocks
                   continue
               if "'jmp'" in repr(last_instruction2):   
                 if "inc" in repr(last_instruction):   
                     if "dec" in repr(instruction):
                        jmp_address     = last_instruction2[1]                               # the address of the jmp instruction itself
                        target_address = int(repr(last_instruction2[0][2]).strip("'"),16)    # the target of the jmp instruction
                        # if we jump right back into the mov instruction
                        if target_address-jmp_address == 1 :
                          bv.write(jmp_address, b"\x90\x90\x90\x90\x90")
                          patchCount = patchCount + 1
                          binaryninja.log_info(repr(last_instruction2))   
                          binaryninja.log_info(repr(last_instruction))   
                          binaryninja.log_info(repr(instruction))  
                          binaryninja.log_info(repr(target_address-jmp_address))   
            last_instruction2 = last_instruction
            last_instruction = instruction
         end = time.time()
         binaryninja.log_info("Done. Finished in {} seconds.".format(end-start))
         binaryninja.log_info("{} patches performed.".format(patchCount))

def clean_tricks_mov_xor_je(bv):
         # mov REG, CODE -> xor REG,REG -> je CODE
         # careful! xor REG,REG may be legitimate...
         start = time.time()
         patchCount = 0
         instructionList = bv.instructions
         last_instruction = None
         last_instruction2 = None
         for instruction in instructionList:
              if last_instruction2 is not None:
               if "'mov'" in repr(last_instruction2):   
                 if "xor" in repr(last_instruction):   
                   if repr(last_instruction[0][2]) == repr(last_instruction[0][4]):    # xor has to happen on single register 
                    if repr(last_instruction2[0][2]) == repr(last_instruction[0][2]):  # mov and xor has to happen on identical register 
                     if "je" in repr(instruction):
                        mov_address     = last_instruction2[1]                         # the address of the mov instruction itself
                        target_address = int(repr(instruction[0][2]).strip("'"),16)    # the target of the je instruction
                        if target_address-mov_address == 2 :                           # if we jump right back into the mov instruction
                          bv.write(mov_address, b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90")    # NOP away obfuscating content
                          patchCount = patchCount + 1
                          binaryninja.log_info(repr(last_instruction2))   
                          binaryninja.log_info(repr(last_instruction))   
                          binaryninja.log_info(repr(instruction))  
              last_instruction2 = last_instruction
              last_instruction = instruction
         end = time.time()
         binaryninja.log_info(repr(end-start))
         binaryninja.log_info("Done. Finished in {} seconds.".format(end-start))
         binaryninja.log_info("{} patches performed.".format(patchCount))

def clean_tricks_mov_xor_je_sorted(bv):
         # mov REG, CODE -> xor REG,REG -> je CODE
         # careful! xor REG,REG may be legitimate...
         start = time.time()
         patchCount = 0
         instructionList = sorted(bv.instructions, key=itemgetter(1)) # sort instructions by address. BN does not provide this in order
         last_instruction = None
         last_instruction2 = None
         last_instruction3 = None
         last_instruction4 = None
         last_instruction5 = None
         for instruction in instructionList:
              if last_instruction5 is not None:
               if repr(instruction) in [repr(last_instruction),repr(last_instruction2),repr(last_instruction3),repr(last_instruction4),repr(last_instruction5)]: # ignore repeated/duplicate code blocks
                    continue
               if "'mov'" in repr(last_instruction5):   
                 if last_instruction5[1] == 0x004d52c6 :
                                        binaryninja.log_info(repr(last_instruction5))   
                                        binaryninja.log_info(repr(last_instruction4))   
                                        binaryninja.log_info(repr(last_instruction3))   
                                        binaryninja.log_info(repr(last_instruction2))   
                                        binaryninja.log_info(repr(last_instruction))   
                                        binaryninja.log_info(repr(instruction)) 
                 if "'inc'" in repr(last_instruction4):   
                   if "'dec'" in repr(last_instruction3):
                     if "jmp" in repr(last_instruction2):
                       if "xor" in repr(last_instruction):
                         if "je" in repr(instruction):
                           if repr(last_instruction[0][2]) == repr(last_instruction[0][4]):          # xor has to happen on identical register 
                            if repr(last_instruction[0][2]) == repr(last_instruction5[0][2]):        # mov and xor has to happen on identical register 
                                      mov_address     = last_instruction5[1]                         # the address of the mov instruction itself
                                      target_address = int(repr(instruction[0][2]).strip("'"),16)    # the target of the je instruction
                                      if target_address-mov_address == 2 :                           # if we jump right back into the mov instruction
                                        bv.write(mov_address, b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90")    # NOP away obfuscating content
                                        patchCount = patchCount + 1
                                        binaryninja.log_info(repr(last_instruction5))   
                                        binaryninja.log_info(repr(last_instruction4))   
                                        binaryninja.log_info(repr(last_instruction3))   
                                        binaryninja.log_info(repr(last_instruction2))   
                                        binaryninja.log_info(repr(last_instruction))   
                                        binaryninja.log_info(repr(instruction))  
              last_instruction5 = last_instruction4
              last_instruction4 = last_instruction3
              last_instruction3 = last_instruction2
              last_instruction2 = last_instruction
              last_instruction = instruction
         end = time.time()
         binaryninja.log_info(repr(end-start))
         binaryninja.log_info("Done. Finished in {} seconds.".format(end-start))
         binaryninja.log_info("{} patches performed.".format(patchCount))

def clean_tricks_inc_dec(bv):
         # jmp (overlaps inc instruction) -> inc REG -> dec REG
         start = time.time()
         patchCount = 0
         instructionList = sorted(bv.instructions, key=itemgetter(1)) # sort instructions by address. BN does not provide this in order
         last_instruction = None
         for instruction in instructionList:
            if last_instruction is not None:
               if repr(instruction[0]) == repr(last_instruction[0]):  # ignore repeated/duplicate code blocks
                   continue
               if "inc" in repr(last_instruction):   
                   if "dec" in repr(instruction):
                     if repr(last_instruction[0][2]) == repr(instruction[0][2]):    # inc/dec has to happen on identical register 
                          bv.write(last_instruction[1], b"\x90\x90\x90\x90\x90\x90")
                          patchCount = patchCount + 1
                          binaryninja.log_info(repr(last_instruction))   
                          binaryninja.log_info(repr(instruction))  
            last_instruction = instruction
         end = time.time()
         binaryninja.log_info("Done. Finished in {} seconds.".format(end-start))
         binaryninja.log_info("{} patches performed.".format(patchCount))

def clean_tricks_xor_je(bv):
         # xor REG,REG -> je ADDR
         start = time.time()
         patchCount = 0
         instructionList = sorted(bv.instructions, key=itemgetter(1)) # sort instructions by address. BN does not provide this in order
         last_instruction = None
         last_instruction2 = None
         for instruction in instructionList:
            if last_instruction is not None:  
               if repr(instruction[0]) == repr(last_instruction[0]):  # ignore repeated/duplicate code blocks
                   continue
               if "xor" in repr(last_instruction):   
                   if "je" in repr(instruction):
                     if repr(last_instruction[0][2]) == repr(last_instruction[0][4]):        # xor has to happen on single register            
                              bv.always_branch(instruction[1])
                              start_addr = bv.get_previous_function_start_before(last_instruction[1])
                              func = bv.get_function_at(start_addr)
                              patchCount = patchCount + 1
                              if func is not None: 
                                   func.set_user_instr_highlight(last_instruction[1], HighlightStandardColor.BlueHighlightColor)
                              start_addr = bv.get_previous_function_start_before(instruction[1])
                              func = bv.get_function_at(start_addr)
                              if func is not None: 
                                   func.set_user_instr_highlight(instruction[1], HighlightStandardColor.BlueHighlightColor)
                              binaryninja.log_info(repr(last_instruction))   
                              binaryninja.log_info(repr(instruction)) 
            last_instruction = instruction
         end = time.time()
         binaryninja.log_info(repr(end-start))
         binaryninja.log_info("Done. Finished in {} seconds.".format(end-start))
         binaryninja.log_info("{} patches performed.".format(patchCount))

def clean_tricks_je_jne(bv):
         # je ADDR -> jne ADDR
         start = time.time()
         patchCount = 0
         instructionList = sorted(bv.instructions, key=itemgetter(1)) # sort instructions by address. BN does not provide this in order
         last_instruction = None
         last_instruction2 = None
         for instruction in instructionList:
            if last_instruction2 is not None:  
               if repr(instruction) == repr(last_instruction):  # ignore repeated/duplicate code blocks
                   continue
               if repr(instruction) == repr(last_instruction2): # ignore repeated/duplicate code blocks
                   continue
               if "je" in repr(last_instruction):   
                   if "jne" in repr(instruction):        
                         address1 = int(repr(last_instruction[0][2]).strip("'"),16)          # the target of the je instruction       
                         address2 = int(repr(instruction[0][2]).strip("'"),16)               # the target of the jne instruction
                         if address2 > (instruction[1] + 1):                                 # make sure target is at least two bytes further than the jne instruction itself        
                           if address1 == address2:
                              patchCount = patchCount + 1
                              bv.always_branch(last_instruction[1])
                              start_addr = bv.get_previous_function_start_before(last_instruction[1])
                              func = bv.get_function_at(start_addr)
                              if func is not None: 
                                   func.set_user_instr_highlight(last_instruction[1], HighlightStandardColor.BlueHighlightColor)
                              start_addr = bv.get_previous_function_start_before(instruction[1])
                              func = bv.get_function_at(start_addr)
                              if func is not None: 
                                   func.set_user_instr_highlight(instruction[1], HighlightStandardColor.BlueHighlightColor)
                              binaryninja.log_info(repr(last_instruction2))   
                              binaryninja.log_info(repr(last_instruction))   
                              binaryninja.log_info(repr(instruction)) 
            last_instruction2 = last_instruction
            last_instruction = instruction
         end = time.time()
         binaryninja.log_info(repr(end-start))
         binaryninja.log_info("Done. Finished in {} seconds.".format(end-start))
         binaryninja.log_info("{} patches performed.".format(patchCount))

def clean_tricks_all(bv):
     clean_tricks_je_jne(bv)
     clean_tricks_push_xor_je_pop(bv)
     clean_tricks_jmp_inc_dec(bv)
     clean_tricks_mov_xor_je(bv)
     clean_tricks_mov_xor_je_sorted(bv)
     clean_tricks_inc_dec(bv)
     clean_tricks_xor_je(bv)


PluginCommand.register("Clean Tricks\\0 - Empty template", "Empty template to experiment with", clean_tricks_template)
PluginCommand.register("Clean Tricks\\1 - Patch 'je ADDR-> jne ADDR' (forward)"         , "Patches all 'je ADDR -> jne ADDR' to jmp", clean_tricks_je_jne) 
PluginCommand.register("Clean Tricks\\2 - Patch 'push REG, xor REG,REG, je, pop REG'"         , "Patches all 'push REG, xor REG,REG, je, pop REG' to nop", clean_tricks_push_xor_je_pop) 
PluginCommand.register("Clean Tricks\\3 - Patch 'jmp -> inc REG -> dec REG' (jmp,inc overlap)", "Patches all 'jmp - > inc REG -> dec REG' to nops", clean_tricks_jmp_inc_dec)
PluginCommand.register("Clean Tricks\\4 - Patch 'mov REG -> xor REG,REG -> je'" , "Patches all 'mov REG -> xor REG,REG -> je'  to 'nop'" , clean_tricks_mov_xor_je) 
PluginCommand.register("Clean Tricks\\5 - Patch 'mov REG -> xor REG,REG -> je' (sort instructions)" , "Patches all 'mov REG -> xor REG,REG -> je'  to 'nop' using a sorted list for the instructions" , clean_tricks_mov_xor_je_sorted) 
PluginCommand.register("Clean Tricks\\6 - Patch 'inc REG -> dec REG'", "Patches all 'inc REG -> dec REG' to nops", clean_tricks_inc_dec)
PluginCommand.register("Clean Tricks\\7 - Patch 'xor REG,REG -> je ADDR'"         , "Patches all 'XOR REG,REG -> je ADDR' to jmp", clean_tricks_xor_je) 
PluginCommand.register("Clean Tricks\\8 - Patch all"         , "Run all tricks", clean_tricks_all) 

