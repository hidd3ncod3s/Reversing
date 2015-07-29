import pefile 
import immlib 
import libanalyze

def print_sym(imm,sym): 
    imm.Log( "%s == 0x%08X"%(sym.getName(),sym.getAddress()))

# 
""""return the key of dictionary dic given the value"""
# 
def find_key(dic, val): 
    return [k for k, v in dic.iteritems() if v == val][0]

def isTargetaddressInteresting(imm, addr, dest,target_module):
    ”’is an address within range of a interesting DLL”’
    mod = imm.getModuleByAddress(addr)
    if (dest < mod.getBaseAddress()) or (dest > mod.getBaseAddress()+mod.getSize()):
        # pointing to a location other than the source module
        #module = imm.getModuleByAddress(dest)
        module = imm.findModule(dest)
        if not module :
            #No module is found. May be it is pointing to heap
            return True
        else:
            #all_modules=imm.getAllModules()
            mod=imm.getModule(module[0].lower())
            #module_name= (find_key(all_modules,mod)).toLower()
            #imm.log(“%s”%module[0].lower())
            if mod == target_module:
                return True
            #elif module[0] == target_module:
            #    return True
    return False

def main(args): 
    imm = immlib.Debugger()
    all_modules=imm.getAllModules()
    for module in all_modules.values():
        imm.log("Module name %s" % find_key(all_modules,module)) 
        if module.symbols:
            for Sym in module.symbols.values():
                if “export” in Sym.getType().lower():
                    disassembled=imm.disasm(Sym.getAddress())
                    if disassembled.isJmp():
                        opstring= disassembled.getDisasm()
                        jmpaddr = disassembled.getJmpAddr()
                        if isTargetaddressInteresting(imm,Sym.getAddress(),jmpaddr,"injected.dll"):
                            #imm.log(“Module name %s”% find_key(all_modules,module)) 
                            #imm.log(”             %s”%opstring)
                            imm.log("             %s == 0x%08X" % (Sym.getName(),Sym.getAddress()))
                            #findModule
    return "success"