import pathlib
from setuptools import setup

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()
setup(
    name="adnuntius",
    version="1.10.1",
    description="Interface and tools for using the Adnuntius API",
    long_description="Interface and tools for using the Adnuntius API",
    url="https://github.com/Adnuntius/api-tools",
    author="Adnuntius",
    author_email="tech@adnuntius.com",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
    ],
    packages=["adnuntius"],
    install_requires=["python-dateutil", "requests", "requests_toolbelt"],
)
