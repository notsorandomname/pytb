
from setuptools import setup
from setuptools.extension import Extension

description = 'Utility for viewing stacktraces of running python processes'

try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except (IOError, ImportError):
    try:
        long_description = open('README.md').read()
    except (IOError, ImportError):
        long_description = description

packages = {
    'pytb': 'py-modules/',
    'pytb.scripts': 'py-modules/scripts'
}

setup(
    name="pytb",
    version="0.0.10",
    author="mitmeedle",
    author_email="mitmeedle@gmail.com",
    entry_points={
        'console_scripts': [
            'pytb = pytb.scripts.pytb:main',
        ]
    },
    packages=packages,
    package_dir=packages,
    description=description,
    long_description=long_description,
    url='https://github.com/notsorandomname/pytb',
    classifiers = [
        'Programming Language :: Python :: 2 :: Only',
        'Topic :: System :: Monitoring',
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
    ]
)
