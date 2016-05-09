from glob import glob
from os.path import basename
from os.path import splitext

from setuptools import find_packages
from setuptools import setup


def readme():
    with open('README.md') as readme_file:
        return readme_file.read()


setup(
    name='secrets',
    version='0.0.0',
    description='A module which provides the common crypto operations for the app',
    long_description=readme(),
    keywords='system secret cryptography random',
    url='http://github.com/silver-saas/silver',
    author='Horia Coman',
    author_email='horia141@gmail.com',
    license='All right reserved',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    py_modules=[splitext(basename(path))[0] for path in glob('src/*.py')],
    install_requires=[
        'bcrypt==2.0.0',
        # For testing
        'coverage==4.1b1',
        'mockito==0.5.2',
        'tabletest==1.1.0',
        ],
    test_suite='tests',
    tests_require=[],
    include_package_data=True,
    zip_safe=False
)
