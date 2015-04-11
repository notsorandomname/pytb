
import contextlib
import subprocess
import tempfile

identity = lambda val: val

# Painless support of lineprof

try:
    profile
except NameError:
    profile = identity

@contextlib.contextmanager
def cmd_as_file(cmd, *args, **kwargs):
    """Launch `cmd` and treat its stdout as a file object"""
    kwargs['stdout'] = subprocess.PIPE
    stdin = kwargs.pop('stdin', None)
    if isinstance(stdin, basestring):
        with tempfile.TemporaryFile() as stdin_file:
            stdin_file.write(stdin)
            stdin_file.seek(0)
            kwargs['stdin'] = stdin_file
            p = subprocess.Popen(cmd, *args, **kwargs)
    else:
        p = subprocess.Popen(cmd, *args, **kwargs)
    try:
        yield p.stdout
    finally:
        p.stdout.close()
        if p.wait():
            raise subprocess.CalledProcessError(p.returncode, cmd)

