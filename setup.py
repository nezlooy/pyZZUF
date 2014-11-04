#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
	from setuptools import setup
except ImportError:
	from distutils.core import setup

config = {
	'name': 'pyZZUF',
	'description': 'Python implementation of zzuf mutator - little bit-flip atomic bomb',
	'platforms': ['POSIX', 'Windows'],
	'author': '@nezlooy',
	'url': 'https://github.com/nezlooy/pyZZUF',
	'keywords': 'fuzzer zzuf mutator',
	'author_email': 'r.bazhin@gmail.com',
	'version': '0.1',
	'packages': ['pyZZUF'],
	'package_dir': {
		'pyZZUF': '.'
	},
	'classifiers': [
		'Development Status :: 5 - Production/Stable',
		'Programming Language :: Python',
		'Topic :: Software Development :: Testing',
		'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
	],
}

setup(**config)