# filepath: /Users/cc/college/spring_2025/comp_991/pcap_reader/setup.py
from setuptools import setup, Extension

module = Extension(
    'pcap_parser',
    sources=['src/pcap_parser_final.c'],
    libraries=['pcap'],
)

setup(
    name='pcap_parser',
    version='1.0',
    description='PCAP parser with Python bindings',
    ext_modules=[module],
)