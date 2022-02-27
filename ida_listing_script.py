import idc
import ida_pro
import ida_nalt

idc.auto_wait()
idc.gen_file(idc.OFILE_LST , str(ida_nalt.get_root_filename()) + "_listing.lst", 0, idc.BADADDR, 0)

ida_pro.qexit()