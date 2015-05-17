
from setuptools import setup
from setuptools.extension import Extension

try:
   import pypandoc
   description = pypandoc.convert('README.md', 'rst')
except (IOError, ImportError):
   description = open('README.md').read()

packages = {
    'pytb': 'py-modules/',
    'pytb.scripts': 'py-modules/scripts'
}

setup(
    name="pytb",
    version="0.0.5",
    author="mitmeedle",
    author_email="mitmeedle@gmail.com",
    entry_points={
        'console_scripts': [
            'pytb = pytb.scripts.pytb:main',
        ]
    },
    packages=packages,
    package_dir=packages,
    description='Utility for viewing stacktraces of running python processes',
    long_description=description
)
