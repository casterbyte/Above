from setuptools import setup, find_packages

setup(
    name="above",
    version="2.3",
    url="https://github.com/cursedpkt/above",
    author="Magama Bazarov",
    author_email="cursedpkt@gmail.com",
    scripts=['above.py'],
    description="Invisible Network Protocol Sniffer",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    license="Apache-2.0",
    keywords=['penetration testing', 'network security', 'network sniffer'],
    packages=find_packages(),
    install_requires=[
        'scapy',
        'colorama',
    ],
    py_modules=['pcap_analyzer'],
    entry_points={
        "console_scripts": ["above = above:main"],
    },
    python_requires='>=3.11',
)