This repository is an implementation of AES-128bit CTR mode by Group 35 - Attending course 02231 Cryptography Fundamentals Fall 2025

### Compilation and Installation
Python is interpreted so there is no compilation. Below are instructions to set up a Python environment and installthe required library on Ubuntu 24.04.2 LTS as specified by the assignment.
* Operating System: Ubuntu 24.03.2 LTS
* Python: Python 3.11 or newer
* pip: Python package installer

#### Python packages
* Pycryptdome which provides Crypto.Cipher.AES and Crypto.Random.get_random_bytes

### Steps to run
sudo apt install -y python3 python3-pip
pip install --upgrade pip

pip install -r requirements.txt
OR
sudo pip install pycryptodome

Verify installation with:
pip show pycryptodome

### Running and interpreting the tests
To run the tests, simply run the implementation.py file. The program will print the tests in the console. 
The first test shows that a message can be encrpyted and decrypted again succesfully.
The second tests shows that changing a single bit in the ciphertext results in a single changed bit in the plaintext. This property shows that CTR-mode is not IND-CCA secure. 
