import bcrypt
import argparse
import time
from tqdm import tqdm
from datetime import timedelta
from multiprocessing import Pool, Manager, cpu_count
import os


def parse_bcrypt_hash(bcrypt_hash: str):
    parts = bcrypt_hash.split('$')
    if len(parts) != 4:
        raise ValueError("Hash is invalid or does not conform to bcrypt format.")
    
    version = parts[1]
    cost = parts[2]
    full = parts[3]
    salt = full[:22]
    hashed = full[22:]

    return {
        "version": version,
        "cost": cost,
        "salt": salt,
        "hash": hashed
    }


def check_password(args):
    password, target_hash = args
    try:
        if bcrypt.checkpw(password.encode(), target_hash.encode()):
            return password
    except:
        return None
    return None


def crack_bcrypt(target_hash: str, wordlist_path: str):
    print(f"[+] Target Hash    : {target_hash}")

    try:
        info = parse_bcrypt_hash(target_hash)
        print(f"[~] Hash Info:")
        print(f"    - Bcrypt Version : {info['version']}")
        print(f"    - Cost Factor    : {info['cost']} (2^{info['cost']} = {2 ** int(info['cost'])} iterations)")
        print(f"    - Salt           : {info['salt']}")
        print(f"    - Hash           : {info['hash']}")
    except Exception as e:
        print(f"[!] Error parsing hash: {e}")
        return

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        print(f"[+] Wordlist Loaded: {len(passwords)} words\n")
    except Exception as e:
        print(f"[!] Error load wordlist: {e}")
        return

    start_time = time.time()

    found_password = None
    try:
        with Pool(processes=cpu_count()) as pool:
            args_list = [(password, target_hash) for password in passwords]
            for result in tqdm(pool.imap_unordered(check_password, args_list), total=len(passwords), desc="🔍 Cracking", unit="pass"):
                if result:
                    found_password = result
                    pool.terminate()
                    break
    except KeyboardInterrupt:
        print("\n[!] Stoped by user.")
        return

    duration = timedelta(seconds=int(time.time() - start_time))

    if found_password:
        print(f"\n[✅] Password Found: {found_password}")
        with open("result.txt", "w") as f:
            f.write(f"Hash: {target_hash}\nPassword: {found_password}\n")
        print("[💾] Saved in result.txt")
    else:
        print("\n[❌] Password not Found.")

    print(f"[⏱️] Time: {duration}")


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="becryptor (multi-core bcrypt cracker 😎)")
    parser.add_argument('--hash', required=True, help='Hash bcrypt target')
    parser.add_argument('--wordlist', required=True, help='Path ke wordlist')

    args = parser.parse_args()
    crack_bcrypt(args.hash, args.wordlist)

def print_banner():
    banner = """
██████╗  ██████╗██████╗ ██╗   ██╗██████╗ ████████╗      
██╔══██╗██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝      
██████╔╝██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║         
██╔══██╗██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║         
██████╔╝╚██████╗██║  ██║   ██║   ██║        ██║         
╚═════╝  ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝         
                                                        
██████╗ ██████╗ ███████╗ █████╗ ██╗  ██╗███████╗██████╗ 
██╔══██╗██╔══██╗██╔════╝██╔══██╗██║ ██╔╝██╔════╝██╔══██╗
██████╔╝██████╔╝█████╗  ███████║█████╔╝ █████╗  ██████╔╝
██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═██╗ ██╔══╝  ██╔══██╗
██████╔╝██║  ██║███████╗██║  ██║██║  ██╗███████╗██║  ██║
╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                                              by bl4nk          
    """
    print(banner)
if __name__ == '__main__':
    main()

