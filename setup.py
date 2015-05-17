
from setuptools import setup
from setuptools.extension import Extension

packages = {
    'voodoo': 'py-modules/',
    'voodoo.scripts': 'py-modules/scripts'
}

setup(
    name="pytb",
    version="0.0.1",
    author="mitmeedle",
    author_email="mitmeedle@gmail.com",
    entry_points={
        'console_scripts': [
            'pystack = voodoo.scripts.pystack:main',
        ]
    },
    packages=packages,
    package_dir=packages,
)
