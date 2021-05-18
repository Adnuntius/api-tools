# Api Tools

An interface for a Python 3+ client to interact with the Adnuntius Advertising and Data APIs. 

## Installation

The simplest way to install the latest production release is via pip
```
pip3 install adnuntius
```

All production (not pre-release) releases from this repository are available in Pypi for installation via pip.
You can select a particular version in pip with the `==` operator, for example `pip3 install adnuntius==1.4.3`

Note that semantic versioning is used for production releases, so major versions indicate incompatible API changes, 
minor versions indication additions to the api, and patch versions indicate backwards compatible bug fixes.

For non-production releases you can download and extract the tarball and use the following commands to install
```
python3 setup.py build
sudo python3 setup.py install
```

## Usage

A good way to get started is to look at test/example_line_item.py. 
To see this in action fist run `python3 -m test.example_line_item -h` to list the arguments you need. 
If you prefer to run in an IDE, an "ExampleLineItem" launcher is included to run it in IntelliJ IDEA and PyCharm.

## Build

`python3 setup.py sdist bdist_wheel`

### Test

A test suite is run via github actions on every push. 
It can be executed manually via `python3 -m test.test_adnuntius` or the "TestAdnuntius" launcher.

### Lint

The flake8 linter is run via github actions on every push.
It can be installed via pip (`pip install flake8`) and run manually.
The build stopping errors can be seen with `flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics`.
The warnings can be seen with `flake8 . --count --exit-zero --max-complexity=10 --max-line-length=120 --statistics`

## [Contact Us](https://adnuntius.com/contact-us/)
