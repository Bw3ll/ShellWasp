from setuptools import setup, find_packages
import os
import re

NAME = "ShellWasp"
VERSION = "2.1.1"
REQUIREMENTS = [
    "colorama>=0.4.4",
    "keystone-engine>=0.9.2",
    "openai>=1.0.0",
]

setup(
    name='ShellWasp: 32-bit Syscall Shellcode Generator',
    author='Bramwell Brizendine',
    description='ShellWasp - Generating 32-bit, WoW64 shellcode with Windows Syscalls',
    version=VERSION,
    long_description="Words",
    url='https://github.com/',
    include_package_data=True,
    packages=find_packages(),
    install_requires=REQUIREMENTS,
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
    python_requires='>=3.6',
)

