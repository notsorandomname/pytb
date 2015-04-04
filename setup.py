
from setuptools import setup
from setuptools.extension import Extension
from Cython.Distutils import build_ext

voodoo_core = Extension('voodoo.core', ['voodoo/voodoo.core.pyx'])
voodoo_cpython = Extension('voodoo.cpython', ['voodoo/voodoo.cpython.pyx'])

pystack_script = Extension('voodoo.scripts.pystack', ['voodoo/scripts/voodoo.scripts.pystack.pyx'])

packages = {
    'voodoo': 'voodoo/',
    'voodoo.scripts': 'voodoo/scripts'
}

setup(
    name="voodoo",
    version="0.0.1",
    author="xxx",
    author_email="xxx@gmail.com",
    entry_points={
        'console_scripts': [
            'pystack = voodoo.scripts.pystack:main',
        ]
    },
    packages=packages,
    ext_modules=[voodoo_core, voodoo_cpython, pystack_script],
    cmdclass={'build_ext': build_ext}
)
