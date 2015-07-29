import idc 
import sys 
import string 
import idaapi 
import idautils 
import string

YN= AskYN(0,"Do you know number of cases, addr of first array and second array."); 
if YN== -1 or YN==0: 
    raise ValueError,"Didn’t do any modification"

numberofcases= AskLong(0x0, "Enter number of cases with this switch case") 
case_string  = AskStr("case_","Enter the string you want to use to tag the cases") 
if(case_string == 0): 
    case_string= "case_" 
first_b_array= AskAddr(0,"Enter First Array Pointer") 
second_dw_array= AskAddr(0, "Enter Second Array Pointer")

YN= AskYN(0,"This script will modify your names. Be careful with the value you entered"); 
if YN== -1 or YN==0: 
    raise ValueError,"Didn’t do any modification"

if (numberofcases != -1 and first_b_array !=0x0 and second_dw_array != 0x0 ): 
    print "[DEBUG]Number of cases: %d"%numberofcases 
    
    current_case=0; 
    
    for ptr in range(first_b_array, first_b_array + numberofcases): 
        second_array_index= Byte(ptr); 
        
        case_addr= Dword(second_dw_array+ (second_array_index*4)); 
        oldname= GetTrueName(case_addr) 
        newname = "" 
        
        if "loc_" in oldname: 
            # we create completely new name here 
            # NEED: Fix this based on the case numbering. 
            newname = "%s_%d"%(case_string,current_case); 
        else: 
            # NEED: Fix this based on the case numbering. 
            newname = "%s_%d"%(oldname,current_case); 
        
        MakeNameEx(case_addr, newname,SN_NOCHECK); 
        
        print "[DEBUG]case_addr: 0x%x old case name: %s New name: %s"%(case_addr,oldname,newname) 
        current_case = current_case + 1;