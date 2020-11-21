import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

requires = [
    "requests>=2.21.0",
    "grequests>=0.6.0",
    "pycryptodome>=3.9.7",
    "flask8>=3.8.4"
]
setuptools.setup(
    name="padding-oracle-attack", # Replace with your own username
    version="0.0.5",
    author="lcark",
    author_email="lcark@foxmail.com",
    description="a library for padding oracle attack",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/lcark/padding_oracle_attack/",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.3',
    install_requires=requires,
)