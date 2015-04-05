
from setuptools import setup
from setuptools.extension import Extension

packages = {
    'voodoo': 'py-modules/',
    'voodoo.scripts': 'py-modules/scripts'
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
)
