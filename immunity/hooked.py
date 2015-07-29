import pefile 
import immlib 
import libanalyze

def print_sym(imm,sym): 
        imm.Log( "%s == 0x%08X"%(sym.getName(),sym.getAddress()))

# 
"""return the key of dictionary dic given the value"""
# 
def find_key(dic, val): 
    return [k for k, v in dic.iteritems() if v == val][0]

def main(args): 
    imm = immlib.Debugger() 
    all_modules=imm.getAllModules() 
    for module in all_modules.values(): 
        imm.Log("Module name %s"% find_key(all_modules,module)) 
        if module.symbols : 
            for Sym in module.symbols.values(): 
                    if ‘export’ in Sym.getType().lower(): 
                        disassembled=imm.disasm(Sym.getAddress()) 
                        if disassembled.isJmp(): 
                           imm.Log("\t%s == 0x%08X"%(Sym.getName(),Sym.getAddress()))