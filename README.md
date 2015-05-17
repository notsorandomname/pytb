# pytb
Utility for inspecting python stack of running process (x64 linux only)

Installation:
---

```pip install pytb```

Usage:
---

```sudo pytb [pid]```

will show you stacktrace of each python thread.

If you want to also see greenlet stacktraces, use

```sudo pytb -g [pid]```

this will also show you greenlets stacktraces.
NOTE: in order to find all greenlets pytb looks for all gc tracked objects, so this may take a while if you have lots of objects.

Notes:
---
Supports viewing python2 and python3 tracebacks (it will try to guess, whether it's 2 or 3, however you can help it by specifying -2 or -3 option)

The utility works by reading ```/proc/<pid>/mem``` (this is why sudo is needed). It uses *nm* and *objdump*
for finding inner python structures in memory.

It's also possible that python process is compiled with different flags that influence inner python's structure fields alignment (on which *pytb* heavily relies)
In this case you can run it with ```-d python-executable``` option
where ```python-executable``` is an executable that contains debug symbols for the process you are interested in.
*pytb* will launch gdb in this case and ask it for offsets of fields it's interested in.

There is also a gotcha that ```frame->f_code->co_filename``` contains not an absolute path, but relative, and if your process has chdir'ed somewhere, those relative paths will become invalid (they are used when rendering stacktraces). For this situation there is ```--scriptdir dir``` argument which defaults to ```/proc/<pid>/cwd``` and serves as a root for ```co_filename```.