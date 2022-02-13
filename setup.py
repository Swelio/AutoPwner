#!/usr/bin/env python3

import setuptools

with open("./requirements.pip", "r") as f:
    requirements = list(map(str.strip, f.readlines()))

setuptools.setup(
    name="autopwner",
    version="0.0.1",
    author="Swelio",
    license="Apache-2.0",
    packages=setuptools.find_packages(),
    include_package_data=True,
    scripts=["scripts/autopwner"],
    install_requires=requirements,
)
