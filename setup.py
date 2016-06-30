# coding=utf-8
import platform
from distutils.core import setup, Extension


libraries = ['pthread']
if platform.system() != 'Darwin':
    libraries.append('seccomp')
    
setup(name='judger', 
      version='1.0', 
      ext_modules=[Extension('judger', sources=['judger.c', 'runner.c'], 
                                       libraries=libraries)])
