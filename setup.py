from setuptools import setup


def readme():
    with open('README.rst') as f:
        return f.read()


setup(name='pytuxedotouch',
      version='0.1',
      description='Module to communicate with the Honeywell Tuxedo Touch Wifi',
      long_description='Module to communicate with the Honeywell Tuxedo Touch Wifi',
      url='https://github.com/garbled1/pytuxedotouch',
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: Apache Software License',
          'Programming Language :: Python :: 3 :: Only',
          'Topic :: Software Development :: Libraries :: Python Modules'
      ],
      author='Tim Rightnour',
      author_email='root@garbled.net',
      license='Apache 2.0',
      packages=['pytuxedotouch'],
      install_requires=[
          'beautifulsoup4',
          'requests',
          'urllib3',
          'pycryptodome',
      ],
      include_package_data=True,
      zip_safe=False)
