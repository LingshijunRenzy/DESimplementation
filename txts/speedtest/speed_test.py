#!/usr/bin/env python3
import subprocess, time, os, datetime, sys

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    e1des = os.path.abspath(os.path.join(here, '..', '..', 'e1des'))
    random_file = os.path.join(here, 'randomdata.txt')
    key_file = os.path.abspath(os.path.join(here, '..', 'key.txt'))
    iv_file  = os.path.abspath(os.path.join(here, '..', 'iv.txt'))
    modes = ['ECB', 'CBC', 'CFB', 'OFB']
    size_bytes = os.path.getsize(random_file)
    size_mb = size_bytes / (1024 * 1024)
    now = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
    log_file = os.path.join(here, f'test_report_{now}.log')
    with open(log_file, 'w') as log:
        log.write(f'Speed Test Report: {now}\n')
        log.write(f'Random data size: {size_mb:.2f} MB\n')
        for mode in modes:
            # encryption phase
            print(f"Starting {mode} encryption...", flush=True)
            start = time.time()
            enc_file = os.path.join(here, f'enc_{mode}.bin')
            for i in range(20):
                print(f"Encrypting {mode}: {i+1}/20", end='\r', flush=True)
                subprocess.run([e1des, '-p', random_file, '-k', key_file, '-v', iv_file,
                                '-m', mode, '-c', enc_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"\n{mode} encryption completed", flush=True)
            end = time.time()
            enc_ms = (end - start) * 1000
            enc_thr = 20 * size_mb / (end - start)
            log.write(f'{mode} Encrypt: {enc_ms:.2f} ms, {enc_thr:.2f} MB/s\n')
            # decryption phase
            print(f"Starting {mode} decryption...", flush=True)
            start = time.time()
            dec_file = os.path.join(here, f'dec_{mode}.bin')
            for i in range(20):
                print(f"Decrypting {mode}: {i+1}/20", end='\r', flush=True)
                subprocess.run([e1des, '-d', '-p', enc_file, '-k', key_file, '-v', iv_file,
                                '-m', mode, '-c', dec_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"\n{mode} decryption completed", flush=True)
            end = time.time()
            dec_ms = (end - start) * 1000
            dec_thr = 20 * size_mb / (end - start)
            log.write(f'{mode} Decrypt: {dec_ms:.2f} ms, {dec_thr:.2f} MB/s\n')
            # cleanup temporary files
            try:
                os.remove(enc_file)
            except OSError:
                pass
            try:
                os.remove(dec_file)
            except OSError:
                pass
    print(f'Report written to {log_file}')

if __name__ == '__main__':
    main()
