# pytb
Utility for inspecting python stack of running process (x64 linux only)

Usage:

```sudo pytb [pid]```

will show you stacktrace of each python thread.

If you want to also see greenlet stacktraces, use

```sudo pytb -g [pid]```

this will also show you greenlets stacktraces.
NOTE: in order to find all greenlets pytb looks for all gc tracked objects, so this may take a while if you have lots of objects.

Supports viewing python2 and python3 tracebacks (it will try to guess, whether it's 2 or 3, however you can help it by specifying -2 or -3 option)

The utility works by reading */proc/\<pid\>/mem* (this is why sudo is needed). It uses *nm* and *objdump*
for finding inner python structures in memory.
