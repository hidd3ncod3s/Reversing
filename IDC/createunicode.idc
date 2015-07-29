//
//    This idc adds shortcuts to create unicode strings.
//

#include <idc.idc>

static main() 
{
    DelHotkey("Shift+U"");

    AddHotkey("Shift+U","createunicodestring"");
    Message("Press Shift+U @ EA to create unicode string"");
    
    Message("Registered idc functions");
}

// http://www.hex-rays.com/products/ida/support/freefiles/ldrmodules.idc
static MakeNameWithType(ea, type)
{
  auto old_type;
  old_type = GetLongPrm(INF_STRTYPE);
  SetLongPrm(INF_STRTYPE, type);
  MakeStr(ea, BADADDR);
  SetLongPrm(INF_STRTYPE, old_type);
}

static createunicodestring()
{
    auto ea;
    ea= ScreenEA();
    MakeNameWithType(ea,ASCSTR_UNICODE);
}