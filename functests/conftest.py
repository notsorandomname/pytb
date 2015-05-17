
import logging

def pytest_addoption(parser):
    parser.addoption("--python2-dbg", action="store", default="python2.7-dbg",
        help="binary to be launched for symbols lookup")

    parser.addoption("--python3-dbg", action="store", default="python3.4-dbg",
        help="binary to be launched for symbols lookup for py3k")

def pytest_configure(config):
    logging.basicConfig(level=logging.INFO)