# -*- coding:utf-8 -*-

__version__ = "0.5"
__author__ = [
    "Jason Lai <jasonlai256@gmail.com>"
]


from setuptools import setup


setup(name='papyrus',
      version=__version__,
      description='A safely (use AES256 encrypt/decrypt) simple cmd program that manage the infomation of passwords.',
      author='Jason Lai',
      author_email='jasonlai256@gmail.com',
      url='https://github.com/JasonLai256/papyrus',
      py_modules=['papyrus'],
      license="BSD",
      install_requires=[
          'pycrypto',
      ],
      scripts=[
         'bin/papyrus',
      ],
      platforms=["any"],
      classifiers=[
          'Environment :: Console',
          'Intended Audience :: End Users/Desktop',
          'License :: OSI Approved :: BSD License',
          'Operating System :: OS Independent',
          'Programming Language :: Python',
          'Topic :: Office/Business :: Scheduling'
      ],
      test_suite='test_papyrus'
)
