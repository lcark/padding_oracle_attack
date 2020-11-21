import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="lcark", # Replace with your own username
    version="0.0.1",
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
)