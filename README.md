# Api Tools

Python3 interface and tools for using the Adnuntius API.

## Installation

The simplest way to install the module is pip
```
pip install adnuntius
```

## Usage

A good way to get started is to look at test/example_line_item.py. 
To see this in action fist run `python3 -m test.example_line_item -h` to list the arguments you need. 
If you prefer to run in an IDE, an "ExampleLineItem" launcher is included to run it in IntelliJ and PyCharm.

## Contact

https://adnuntius.com/contact-us/

## Building

### Test

Tests can be executed via `python3 -m test.test_adnuntius` or the "TestAdnuntius" launcher.

### Build

```
python3 setup.py sdist bdist_wheel
```

### Package

To upload to test pypi:
```
pip install twine
twine upload --repository-url https://test.pypi.org/legacy/ dist/*
```

To test an install from testpypi
```
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple adnuntius
```

The package can be uninstalled with `pip uninstall adnuntius`.

To upload to the real pypi run the upload command again without the `--repository-url  https://test.pypi.org/legacy/`

