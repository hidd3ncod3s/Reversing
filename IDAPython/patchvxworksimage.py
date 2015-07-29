import idc,sys,string 
from idaapi import *

# make sure you have selected right offset for end_ea ;-))

# vxworks addresses. 
start_ea= 0xDEADBABE; 
end_ea  = 0xDEADBABE;

def GetStringAt(start,end,type): 
    ret_string= ""; 
    while 1: 
        if(Byte(start) != 0x00): 
            ret_string += "%c"%Byte(start); 
            start = start + 1; 
        else: 
            break; 
    return ret_string;

def ret_function_start(ea): 
    function_name= GetFunctionName(ea); 
    function_start= LocByName(function_name) 
    return function_start

def createfunction(func_offset,start_ea): 
    return 1; 
    #print "Map: %x func_offset: %x"%(start_ea,func_offset) 
    if(GetFunctionName(func_offset)): 
        function_start= ret_function_start(func_offset); 
        if (function_start != func_offset): 
            print "%x:: Invalid function %x : %x"%(start_ea,function_start,func_offset); 
            #DelFunction(function_start); 
    else: 
        original_byte= GetOriginalByte(func_offset); 
        if original_byte == 0x55: 
            original_byte= GetOriginalByte(func_offset+1); 
            original_byte2= GetOriginalByte(func_offset+2); 
            if(original_byte == 0x89 and original_byte2 == 0xe5): 
                #print "Creating function at: %x"%(func_offset) 
                MakeFunction(func_offset,BADADDR); 
                return 1; 
    print "%x:: Not function : %x"%(start_ea,func_offset); 
    return 1;

count = 0; 
while start_ea < end_ea: 
    name_offset= Dword(start_ea+0x0); 
    func_offset= Dword(start_ea+0x4); 
    flag1      = Dword(start_ea+0x8); 
    flag2      = Dword(start_ea+0xc); 
    
    # flag1 
    #    0x50000= For function names. 
    #    0x70000= For variable names. 
    #    0x90000= Could be for variables in .bss section. 
    
    
    if(flag1 == 0x50000): 
        count += 1 
        #print "%x : %x"%(start_ea,flag1); 
        #MakeStr(name_offset,BADADDR); 
        #functionname= GetStringAt(name_offset, -1, ASCSTR_C); 
        #if not createfunction(func_offset,start_ea): 
        #    print "Error in creating function @%x"%func_offset; 
        #    #break; 
        #print "Naming function @ 0x%x to %s"%(func_offset,functionname) 
        #if (MakeName(func_offset,functionname)==0): 
        #    print "Cant rename %x : %s "%(func_offset,functionname) 
    
    #if(flag1 == 0x70000): 
    #        #print "%x : %x"%(start_ea,flag1); 
    #        variablename= GetStringAt(name_offset, -1, ASCSTR_C); 
    #        if not MakeByte(func_offset): 
    #            print "Error in creating variable @%x"%func_offset; 
    #            break; 
    #        print "Naming variable @ 0x%x to %s"%(func_offset,variablename) 
    #        #MakeName(func_offset,variablename); 
    
    start_ea= start_ea + 0x10;

print "Total : %d"%count;