from setuptools import setup, Extension
from setuptools.command.install import install
import urllib.request
from subprocess import call
'''
libpcap_url = 'http://www.tcpdump.org/release/libpcap-1.8.1.tar.gz'
flex_url = 'https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz'

def install_libpcap(url):
	req = urllib.request.Request(url)

	f = urllib.request.urlopen(req)
	local_file = open('libpcap.tar', "wb")
	local_file.write(f.read())
	local_file.close()

	call(['tar', '-xf', 'libpcap.tar'])
	call(['./configure', '--prefix=~/usr/local'], cwd='libpcap-1.8.1')
	call(['make'], cwd='libpcap-1.8.1')
	call(['make', 'install'], cwd='libpcap-1.8.1')


def install_flex(url):
	req = urllib.request.Request(url)

	f = urllib.request.urlopen(req)
	local_file = open('flex.tar', "wb")
	local_file.write(f.read())
	local_file.close()

	call(['tar', '-xf', 'flex.tar'])
	call(['./configure', '--prefix=~/usr/local'], cwd='flex-2.6.4')
	call(['make'], cwd='flex-2.6.4')
	call(['make', 'install'], cwd='flex-2.6.4')

class CustomInstall(install):
    def run(self):
        install_flex(flex_url)
        install_libpcap(libpcap_url)
'''
setup(name='libpcapy',
    description='Python library to use libpcap using ctypes',
    version='0.2.0',
    url='https://github.com/alagoa/libpcapy',
    author='Pedro Alagoa',
    author_email='alagoa.pedro@ua.pt',
    license='MIT',
    packages=['libpcapy' ],
    package_data={'libpcapy' : ['data/*']},
   # cmdclass={'install': CustomInstall},
	include_package_data=True,
)