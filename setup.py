from setuptools import setup, find_packages

setup(
    name="sptk",
    version="1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'paramiko',
        'requests',
        'colorama',
        'tqdm',
        'dnspython'
    ],
    entry_points={
        'console_scripts': [
            'sptk = sptk.__main__:main'
        ]
    },
    package_data={
        'sptk': ['wordlists/*.txt']
    }
)