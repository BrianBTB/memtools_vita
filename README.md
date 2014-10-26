-------
Memtools Vita 0.2 (iffy autoresolve)
-------
Allows to play with the Vita's webkit process' memory through by leveraging a webkit vuln. Autoresolve is a little iffy, supports no special cases and skips alot of modules because it crashes (reading invalid memory)

*Install Capstone for python (disassembly library)*

To use, first start the server:
```
    chmod a+x serv.py
    ./serv.py
```
Then with the Vita browse to `http://<ipaddr>:8888`.
If all goes well you will see some output from the `serv.py` script. 
When you see `%> ` it means that initialization is done.
The supported commands are:
- **autodump**  : use to begin recursively resolving the modules
- **savemods** : !unimplemented! save modules to disk (stored in "dump" folder and named as <modname>.bin)
- **x** `addr` `len` : to display `len` bytes from `addr` in a hex-editor-like fashion
- **dis** `addr` `len` `mode` : to disassemble `len` bytes from `addr` in `mode` (thumb or arm, latter is default)
- **dump** `addr` `len` `fname` : to dump `len` bytes from `addr` to `fname`
- **ss** `begaddr` `endaddr` `pattern`: to search for the string `pattern` in [`begaddr`, `endaddr`[
- **reload** : to reload/reset everything
- **exit** : to exit

-----
Manually Dumping
-----
Once you resolve SceWebkit, you will need to look at the module_info to get stub_end. Dump from base of SceWebkit (sce_module.base) to stub end. The dump code appends to existing files with the same name, so delete the old ones if you are redumping for whatever reason. resolve.js implements the memory parsing for resolving a module, give it a look for help.

-----
TODO
-----

- Implement : resume on error (maybe already works, needs better error handling, currently can get very stuck)


- Implement : special-case handling for offsize import list entries

- Implement : doughnut protocol

- Implement : special-case handling for unavailable (but imported) mods (I haven't been -able to dump SceLibKernel manually, may be a bug or it may actually be impossible)


