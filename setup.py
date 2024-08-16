from setuptools import setup, find_packages

setup(
    name="above",
    version="2.7",
    url="https://github.com/casterbyte/above",
    author="Magama Bazarov",
    author_email="caster@exploit.org",
    scripts=['above.py'],
    description="Invisible Network Protocol Sniffer",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    license="Apache-2.0",
    keywords=['network security', 'network sniffer'],
    packages=find_packages(),
    install_requires=[
        'scapy',
        'colorama',
    ],
    entry_points={
        "console_scripts": ["above = above:main"],
    },
    python_requires='>=3.11',
)