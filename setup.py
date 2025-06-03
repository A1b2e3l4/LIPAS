from setuptools import setup, find_packages

setup(
    name='lipas',
    version='1.0.0',
    py_modules=['lipas'],
    install_requires=[
        'requests',
        'dnspython',
        'tldextract',
        'beautifulsoup4'
    ],
    entry_points={
        'console_scripts': [
            'lipas=lipas:main',
        ],
    },
    author='Abel Muturi',
    description='LIPAS - Comprehensive Web Security Assessment Tool',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/lipas',
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: MIT License',
        'Topic :: Security',
    ],
    python_requires='>=3.6',
)
