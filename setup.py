from setuptools import setup
from reverberator import __version__

setup(
    name='reverberator',
    version=__version__,
    description='A inotify based tool to create REVERBs (REcursive VERsioning Backup) using symlinks',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='Yufei Pan',
    author_email='pan@zopyr.us',
    url='https://github.com/yufei-pan/reverberator',
    py_modules=['reverberator'],
    entry_points={
        'console_scripts': [
            'reverberator = reverberator:main',
        ],
    },
    install_requires=[
        'argparse',
		'multiCMD',
		'TSVZ',
		'xxhash',
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: POSIX :: Linux',
    ],
    python_requires='>=3.7',
	license='GPLv3+',
)
