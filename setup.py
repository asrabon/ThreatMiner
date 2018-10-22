from setuptools import setup

setup(name='threatminer',
      version='1.0',
      description="Library to interface with ThreatMiner's API",
      url='https://github.com/asrabon/ThreatMiner',
      author='Sloan Rabon',
      author_email='sloanrabon@gmail.com',
      license='GNU General Public License v3.0',
      packages=['threatminer'],
      install_requires=[
          'urllib3',
          'requests'
      ],
      zip_safe=False)
    