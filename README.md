# AES Cracker
<img width="1429" height="686" alt="{64FC5AB7-D0DF-49AF-81D0-11B3C06AFCEA}" src="https://github.com/user-attachments/assets/44be7e21-6833-4d7b-b007-0d111cfe47f9" />

A simple, fast, and multi-threaded decryption tool.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Stable-success.svg)
![Build](https://img.shields.io/badge/Build-Passing-brightgreen.svg)

## Features

- **Fast:** Runs on all cpu cores.
- **Smart:** Tests common AES modes (CBC, ECB, etc) automatically.
- **Live Stats:** See speed and progress in real-time.
- **Clean UI:** Easy to use terminal interface.

## Quick Start

```bash

# Install
pip install pycryptodomex rich

# Run
python cracker.py
```

## Usage

1. **Select Mode:** Choose a mode or 0 for all.
2. **Paste String:** Enter the encrypted text.
3. **Max Length:** Set the max password length.

