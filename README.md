# Bcrypt Breaker

Bcrypt Breaker is a multi-core bcrypt hash cracker tool written in Python. It leverages the power of multiple CPU cores to efficiently attempt to crack bcrypt hashes using a wordlist.

## Features

- **Multi-core cracking**: Utilizes multiple CPU cores to speed up the cracking process.
- **Bcrypt hash parsing**: Breaks down and identifies information from bcrypt hashes.
- **Lightweight**: Optimized for performance and minimal resource usage, making it faster and less resource-intensive compared to similar tools.
- **Progress display**: Uses `tqdm` to show the cracking progress in the terminal.
- **Result saving**: Cracking results are saved in a `result.txt` file.


## Requirements

- Python 3.x
- A few required dependencies (listed below)

## Installation

1. Clone this repository:

    ```bash
    git clone https://github.com/username/bcrypt-breaker.git
    cd bcrypt-breaker
    ```

2. Install the required dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

To use this tool, run the following command in your terminal:

```bash
python bb.py --hash <BCRYPT_HASH> --wordlist <WORDLIST_PATH>
