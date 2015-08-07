import idc,sys,string
from idaapi import *

_ea= ScreenEA();
ren_function_name= AskStr("_throws_error_","Enter a string for function name");
if ren_function_name==0:
	raise ValueError,"finished"

#print "renaming xref to: %x using name %s"%(_ea,ren_function_name)
xref= RfirstB(_ea);

def hex2dec(s):
	#
	"""return the integer value of a hexadecimal string s"""
	#
	return int(s, 16)

def ret_function_start(ea):
	function_name= GetFunctionName(ea);
	function_start= LocByName(function_name)
	return function_start

def function_exists(function_name):
	if (LocByName(function_name) != BADADDR):
		return True;
	else:
		return False;
	
count=0xBADDBABA;

def find_throw_error_id(cur_ea, func_start):
	error_id= -1;
	
	while cur_ea != BADADDR:
		current_instruction= GetDisasm(cur_ea)
		if(not re.findall(r'push',current_instruction)):
			cur_ea= PrevHead(cur_ea,func_start);
			continue;
		print current_instruction;
		print GetOpnd(cur_ea,0);
		if GetOpType(cur_ea,0) == o_imm:
			error_id= int(GetOpnd(cur_ea,0),10);
		break;
	
	return error_id;

while xref != BADADDR:
	function_name= GetFunctionName(xref);
	function_start= ret_function_start(xref);
	print function_name;
	if (function_name.startswith("sub_")) and (not function_name.startswith(ren_function_name)):
		error_id= find_throw_error_id( xref ,function_start);
		if error_id != -1:
			new_function_name = ren_function_name + "_%d"%(error_id)
		else:
			new_function_name = ren_function_name + "_%d"%(count)
		
		while(function_exists(new_function_name)):
			print new_function_name
			new_function_name= new_function_name + "_"
		
		print "Call_addr:%x function_start: %x oldfuncname: %s newfuncname: %s\n"%(xref,function_start, function_name,new_function_name)
		MakeName(function_start,new_function_name)
		count= count + 1;
	else:
		if (function_name.startswith(ren_function_name)):
			error_id= find_throw_error_id( xref ,function_start);
			if error_id != -1:
				if (not function_name.find("%d" % error_id)):
					new_function_name = function_name + "_%d"%(error_id)
					while(function_exists(new_function_name)):
						new_function_name= new_function_name + "_"
					
					print "Call_addr:%x function_start: %x oldfuncname: %s newfuncname: %s\n"%(xref,function_start, function_name,new_function_name)
					MakeName(function_start,new_function_name)
	
	xref= RnextB(_ea,xref);
	