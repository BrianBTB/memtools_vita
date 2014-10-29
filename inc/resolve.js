function module_info(addr,aspace) {

//size of this struct: 88
//    u16_t   modattribute;  // ?? 0
//    u16_t   modversion;    // always 1,1? 2
//    char    modname[27];   ///< Name of the module 4
//    u8_t    type;          // 6 = user-mode prx? 31
//    void    *gp_value;     // always 0 on ARM 32 32
//    u32_t   ent_top;       // beginning of the export list (sceModuleExports array) 34
//    u32_t   ent_end;       // end of same
//    u32_t   stub_top;      // beginning of the import list (sceModuleStubInfo array)
//    u32_t   stub_end;      // end of same
//    u32_t   module_nid;    // ID of the PRX? seems to be unused
//    u32_t   field_38;      // unused in samples
//    u32_t   field_3C;      // I suspect these may contain TLS info
//    u32_t   field_40;      //
//    u32_t   mod_start;     // module start function; can be 0 or -1; also present in exports
//    u32_t   mod_stop;      // module stop function
//    u32_t   exidx_start;   // ARM EABI style exception tables
//    u32_t   exidx_end;     //
//    u32_t   extab_start;   //
//    u32_t   extab_end;     //
this.base = 0;
this.length = 0x5C;
this.Address = addr;


this.modattribute  =ReadInt16FromAddr(this.Address,aspace);
this.modversion    =ReadInt16FromAddr(this.Address+2,aspace);
this.modname       =readZeroTruncString(this.Address+4,aspace);
this.ent_top       =ReadInt32FromAddr(this.Address+34+2,aspace);
this.ent_end       =ReadInt32FromAddr(this.Address+38+2,aspace);   
this.stub_top      =ReadInt32FromAddr(this.Address+42+2,aspace);  
this.stub_end      =ReadInt32FromAddr(this.Address+46+2,aspace);   
this.module_nid    =ReadInt32FromAddr(this.Address+50+2,aspace);  
this.field_38      =ReadInt32FromAddr(this.Address+54+2,aspace);         
this.field_3C      =ReadInt32FromAddr(this.Address+58+2,aspace);         
this.field_40      =ReadInt32FromAddr(this.Address+62+2,aspace);         
this.mod_start     =ReadInt32FromAddr(this.Address+66+2,aspace);       
this.mod_stop      =ReadInt32FromAddr(this.Address+70+2,aspace);       
this.exidx_start   =ReadInt32FromAddr(this.Address+74+2,aspace);    
this.exidx_end     =ReadInt32FromAddr(this.Address+78+2,aspace);    
this.extab_start   =ReadInt32FromAddr(this.Address+82+2,aspace);    
this.extab_end     =ReadInt32FromAddr(this.Address+86+2,aspace);
this.base = (addr+92-this.ent_top); 


}
module_info.prototype.toString = function(){
logdbg("modattribute  0x"    +this.modattribute.toString(16));
logdbg("modversion    0x"    +this.modversion.toString(16));
logdbg("modname         "      +this.modname);
logdbg("ent_top       0x"    +this.ent_top.toString(16));
logdbg("ent_end       0x"    +this.ent_end.toString(16));
logdbg("stub_top      0x"    +this.stub_top.toString(16));
logdbg("stub_end      0x"    +this.stub_end.toString(16));
logdbg("module_nid    0x"    +this.module_nid.toString(16));
logdbg("field_38      0x"    +this.field_38.toString(16));
logdbg("field_3C      0x"    +this.field_3C.toString(16));
logdbg("field_40      0x"    +this.field_40.toString(16));
logdbg("mod_start     0x"    +this.mod_start.toString(16));
logdbg("mod_stop      0x"    +this.mod_stop.toString(16));
logdbg("exidx_start   0x"    +this.exidx_start.toString(16));
logdbg("exidx_end     0x"    +this.exidx_end.toString(16));
logdbg("extab_start   0x"    +this.extab_start.toString(16));
logdbg("extab_end     0x"    +this.extab_end.toString(16));
return "success";
}
function module_export_entry(addr,aspace){



//    u16_t   size;           // size of this structure; 0x20 for Vita 1.x
//    u8_t    lib_version[2]; //
//    u16_t   attribute;      // ?
//    u16_t   num_functions;  // number of exported functions
//    u32_t   num_vars;       // number of exported variables
//    u32_t   num_tls_vars;   // number of exported TLS variables?  <-- pretty sure wrong // yifanlu
//    u32_t   module_nid;     // NID of this specific export list; one PRX can export several names
//    char    *lib_name;      // name of the export module
//    u32_t   *nid_table;     // array of 32-bit NIDs for the exports, first functions then vars
//    void    **entry_table;  // array of pointers to exported functions and then variables


 this.address = addr;
 this.size           =    ReadInt16FromAddr(addr,aspace);
 this.lib_version    = 	  ReadInt16FromAddr(addr+2,aspace);
 this.attribute      =    ReadInt16FromAddr(addr+4,aspace);
 this.num_functions  =    ReadInt16FromAddr(addr+6,aspace);
 this.num_vars       =    ReadInt32FromAddr(addr+8,aspace);
 this.num_tls_vars   =    ReadInt32FromAddr(addr+12,aspace);
 this.module_nid     =    ReadInt32FromAddr(addr+16,aspace);
 this.lib_name       =    ReadInt32FromAddr(addr+20,aspace);
 this.nid_table      =    ReadInt32FromAddr(addr+24,aspace);
 this.entry_table    =    ReadInt32FromAddr(addr+28,aspace);
 
 
 }
 module_export_entry.prototype.toString = function(){
 logdbg("size            0x:" + this.size.toString(16));
 logdbg("lib_version[2]  0x:" + this.lib_version.toString(16));
 logdbg("attribute       0x:" + this.attribute.toString(16));
 logdbg("num_functions   0x:" + this.num_functions.toString(16));
 logdbg("num_vars        0x:" + this.num_vars.toString(16));
 logdbg("num_tls_vars    0x:" + this.num_tls_vars.toString(16));
 logdbg("module_nid      0x:" + this.module_nid.toString(16));
 logdbg("*lib_name       0x:" + this.lib_name.toString(16));
 logdbg("*nid_table      0x:" + this.nid_table.toString(16));
 logdbg("**entry_table   0x:" + this.entry_table.toString(16));
 return " ";
 }
function module_import_entry(addr,aspace) {
//typedef struct module_imports // thanks roxfan
//{
//    u16_t   size;               // size of this structure; 0x34 for Vita 1.x
//    u16_t   lib_version;        //
//    u16_t   attribute;          //
//    u16_t   num_functions;      // number of imported functions
//    u16_t   num_vars;           // number of imported variables
//    u16_t   num_tls_vars;       // number of imported TLS variables
//    u32_t   reserved1;          // ?
//    u32_t   module_nid;         // NID of the module to link to
//    char    *lib_name;          // name of module
//    u32_t   reserved2;          // ?
//    u32_t   *func_nid_table;    // array of function NIDs (numFuncs)
//    void    **func_entry_table; // parallel array of pointers to stubs; they're patched by the loader to jump to the final code
//    u32_t   *var_nid_table;     // NIDs of the imported variables (numVars)
//    void    **var_entry_table;  // array of pointers to "ref tables" for each variable
//    u32_t   *tls_nid_table;     // NIDs of the imported TLS variables (numTlsVars)
//    void    **tls_entry_table;  // array of pointers to ???
//} module_imports_t;

try{
this.address = addr;
this.size             = ReadInt16FromAddr(addr,aspace);
this.lib_version      = ReadInt16FromAddr(addr+2,aspace);
this.attribute        = ReadInt16FromAddr(addr+4,aspace);
this.num_functions    = ReadInt16FromAddr(addr+6,aspace);
this.num_vars         = ReadInt16FromAddr(addr+8,aspace);
this.num_tls_vars     = ReadInt16FromAddr(addr+10,aspace);
this.reserved1        = ReadInt32FromAddr(addr+12,aspace);
this.module_nid       = ReadInt32FromAddr(addr+16,aspace);
this.lib_name         = ReadInt32FromAddr(addr+20,aspace);
this.reserved2        = ReadInt32FromAddr(addr+24,aspace);
this.func_nid_table   = ReadInt32FromAddr(addr+28,aspace);
this.func_entry_table = ReadInt32FromAddr(addr+32,aspace);
this.var_nid_table    = ReadInt32FromAddr(addr+36,aspace);
this.var_entry_table  = ReadInt32FromAddr(addr+40,aspace);
this.tls_nid_table    = ReadInt32FromAddr(addr+44,aspace);
this.tls_entry_table  = ReadInt32FromAddr(addr+48,aspace);


this.name = readZeroTruncString(this.lib_name,aspace);
if (this.size != 0x34){
logdbg("Warning! off size imports entry: " + this.name + " (" + this.size.toString());
}
}catch(e){
logdbg(e.getMessage());
}
}
module_import_entry.prototype.toString = function() {

logdbg("size               0x" + this.size.toString(16));
logdbg("lib_version        0x" + this.lib_version.toString(16));
logdbg("attribute          0x" + this.attribute.toString(16));
logdbg("num_functions      0x" + this.num_functions.toString(16));
logdbg("num_vars           0x" + this.num_vars.toString(16));
logdbg("num_tls_vars       0x" + this.num_tls_vars.toString(16));
logdbg("reserved1          0x" + this.reserved1.toString(16));
logdbg("module_nid         0x" + this.module_nid.toString(16));
logdbg("*lib_name          0x" + this.lib_name.toString(16));
logdbg("reserved2          0x" + this.reserved2.toString(16));
logdbg("*func_nid_table    0x" + this.func_nid_table.toString(16));
logdbg("**func_entry_table 0x" + this.func_entry_table.toString(16));
logdbg("*var_nid_table     0x" + this.var_nid_table.toString(16));
logdbg("**var_entry_table  0x" + this.var_entry_table.toString(16));
logdbg("*tls_nid_table     0x" + this.tls_nid_table.toString(16));
logdbg("**tls_entry_table  0x" + this.tls_entry_table.toString(16));
logdbg("Name:" + this.name);
return " ";
}


function sce_module(addr,aspace) { 

this.module_info = new module_info(addr,aspace);
this.baseaddr = this.module_info.base;
this.export_list = [];
this.import_list = [];


var info = this.module_info;

//first resolve export list:
var i = info.ent_top;
while (i<info.ent_end)
{
this.export_list[this.export_list.length]=new module_export_entry(info.base+i,aspace);
//logdbg(this.export_list[this.export_list.length-1].toString());
i = i+this.export_list[this.export_list.length-1].size;

}
//now resolve import list
i = info.stub_top;
while (i<info.stub_end)
{
this.import_list[this.import_list.length]=new module_import_entry(info.base+i,aspace);
//logdbg(this.import_list[this.import_list.length-1].toString());
i = i+this.import_list[this.import_list.length-1].size;

}

}

//FULLY WORKING!!!


//DEBUG:
sce_module.prototype.toString = function() {
for (ex in this.export_list){ logdbg(this.export_list[ex].toString()); }
logdbg("");
for (im in this.import_list) { logdbg(this.import_list[im].toString()); }
return "success";
}



//really should use functions from original code but... fix later
function ReadByteFromAddr(i,aspace){
try{
return aspace[i];
}catch(e){
logdbg(e);
return -1
}
}
function ReadInt16FromAddr(i,aspace){
try{
return new Uint16Array(aspace.buffer,i,1)[0];
}catch(e){
logdbg(e);
return -1;
}
}
function ReadInt32FromAddr(i,aspace){
try{
return new Uint32Array(aspace.buffer,i,1)[0];
}catch(e){
logdbg(e);
return -1;
}
return byt
}
function readZeroTruncString(addr,aspace){
i = ReadByteFromAddr(addr,aspace);
str = "";
while (i!== 00){
str += String.fromCharCode(i);
addr++;
i = ReadByteFromAddr(addr,aspace);
}
return str
}

