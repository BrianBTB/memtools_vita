-------
Memtools Vita 0.not_really_a_release_lulz
-------
Allows to play with the Vita's webkit process' memory through by leveraging a webkit vuln.
To use, first start the server:
```
    chmod a+x serv.py
    ./serv.py
```
Then with the Vita browse to `http://<ipaddr>:8888`.
If all goes well you will see some output from the `serv.py` script. 
When you see `%> ` it means that initialization is done.
The supported commands are:
- **resolve** `addr `modname : use resolve 0x82000000 SceWebkit to begin recursively resolving the modules
- **savemods** : !unimplemented! save modules to disk (stored in "dump" folder and named as <modname>.bin)
- **x** `addr` `len` : to display `len` bytes from `addr` in a hex-editor-like fashion
- **dis** `addr` `len` `mode` : to disassemble `len` bytes from `addr` in `mode` (thumb or arm, latter is default)
- **dump** `addr` `len` `fname` : to dump `len` bytes from `addr` to `fname`
- **ss** `begaddr` `endaddr` `pattern`: to search for the string `pattern` in [`begaddr`, `endaddr`[
- **reload** : to reload/reset everything
- **exit** : to exit
