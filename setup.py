from setuptools import setup, find_packages

setup(
    name="above",
    version="2.1",
    url="https://github.com/wearecaster/above",
    author="Caster",
    author_email="casterinfosec@gmail.com",
    scripts=['above.py'],
    description="Autonomous network sniffer for finding network vulnerabilities",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    license="Apache-2.0",
    keywords=['information gathering', 'penetration testing', 'network security', 'network sniffer'],
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
