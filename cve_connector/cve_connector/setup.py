from setuptools import setup, find_packages

setup(
    name='cve_connector',
    version='0.2',
    description='cve connector',
    author='CSIRT-MU, Adam Helc',
    url='',
    packages=find_packages(),
    keywords=['module', 'cve', 'connector'],
    install_requires=['structlog']
)
