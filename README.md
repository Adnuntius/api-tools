# Api Tools

An interface for a Python 3+ client to interact with the Adnuntius Advertising and Data APIs. To get started, pick
one of the two installation methods below (git clone or pip install), and then look at the usage section further down.

## Installation

The following sections assume you have a version of Python 3+ with venv and pip installed and available to you, 
if not you can obtain it:
- On Debian or derivatives such as Ubuntu and Mint with `sudo apt install python3 python3-venv python3-pip`
- On macOS with `brew install python`
- On Microsoft Windows from https://www.python.org/downloads/ (during install, check “Add Python to PATH”)

### Option 1: git clone

This is usually the best option as it allows you to have the files locally, but to use this library as part of another 
project see Option 2. First you will need to `git clone https://github.com/Adnuntius/api-tools.git` and then change 
directory into it (`cd api-tools`). Next you should setup and activate a virtual environment to contain the dependencies 
of this project. For example in linux at the top level directory of this project, you would do:
```
python -m venv .venv
source .venv/bin/activate
```
- For versions of python before 3.3 you will need to install virtualenv (i.e. `brew install virtualenv`) and replace 
`python -m venv .venv` with `virtualenv .venv`.
- On Windows you would replace `source .venv/bin/activate` with `.venv\Scripts\activate`.

### Option 2: pip install

To use the Adnuntius api as part of another library, you can use this option instead of Option 1. The disadvantage
is that you don't have the example files locally, so we add a step at the end to fetch them.
The simplest way to install the latest production release is via pip
```
pip3 install adnuntius
```
All production (not pre-release) releases from this repository are available in Pypi for installation via pip.
As an alternative to the last command, you can select a particular version in pip with the `==` operator, 
for example `pip3 install adnuntius==1.24.0`

Note that semantic versioning is used for production releases, so major versions indicate incompatible API changes, 
minor versions indication additions to the api, and patch versions indicate backwards compatible bug fixes.

For non-production releases you can download and extract the tarball and use the following commands to install
```
python3 setup.py build
python3 setup.py install
```

In either case, to be able to use the usage examples below you will have to clone the example file, on linux:
```
mkdir adn-examples && cd adn-examples && mkdir test
curl -L \
  https://raw.githubusercontent.com/Adnuntius/api-tools/master/test/example_line_item.py \
  -o test/example_line_item.py
chmod +x test/example_line_item.py
```

## Usage

A good way to get started is to look at test/example_line_item.py
To see this in action fist run `python3 -m test.example_line_item -h` from the project dir (if you followed Option 1) 
or adn-examples dir (if you followed Option 2) to list the arguments you need. 
If you used Option 1 and prefer to run in an IDE, an "ExampleLineItem" launcher is included to run it in IntelliJ IDEA 
and PyCharm.

### Authentication and context

As you may be able to see in test/example_line_item.py, authentication is performed as part of setting up the Api() 
object. It supports either a username and password:
```
Api(user, password, 'https://api.adnuntius.com/api', context='...')
```
or an API key:
```
Api(None, None, 'https://api.adnuntius.com/api', api_key=api_key, context='...')
```
The second option with an API key is required if you have 2FA setup on your account, otherwise you will see a 2FA setup 
failure error when attempting to perform any API operations.

Another thing to note is the context parameter must be filled in rather than leaving it as ... This parameter can be
obtained from the Network IDs on the 
[Network page in the Adnuntius Administration User Interface](https://admin.adnuntius.com/admin/network)


## Modifying the library

To modify this library and use it locally, which can be useful for testing, you will need to have completed the Option 
1 steps above. Once these are done, you will also need to set up the libraries you need:
```
pip install --upgrade setuptools
python3 -m pip install twine wheel
```

- Once you have finished making any local changes, you should upversion the `setup.py` and `__init__.py` so that you can 
distinguish your version from the existing one and switch between them if needed.
- To build this new version on linux, you would run `rm -rf dist/ && python3 setup.py sdist bdist_wheel`
- To install this as the default api tools in python, you can install it with 
`python3 -m pip install dist/adnuntius-THE NEW VERSION.tar.gz`

### Test

A test suite is run via github actions on every push. 
It can be executed manually via `python3 -m test.test_adnuntius` or the "TestAdnuntius" launcher if you have python 3.8+

### Lint

The flake8 linter is run via github actions on every push.
It can be installed via pip (`pip install flake8`) and run manually.
The build stopping errors can be seen with `flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics`.
The warnings can be seen with `flake8 . --count --exit-zero --max-complexity=10 --max-line-length=120 --statistics`

## [Contact Us](https://adnuntius.com/contact/)
