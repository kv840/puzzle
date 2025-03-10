import os
import time
import random
import argparse
import re
from bit import Key
from concurrent.futures import ThreadPoolExecutor, as_completed

def valid_hex_range(option):
    match = re.fullmatch(r'([0-9a-fA-F]+):([0-9a-fA-F]+)', option)
    if match:
        return match.groups()
    raise argparse.ArgumentTypeError(f'Invalid hex range: {option}')

print("Starting program, please wait...")
time.sleep(2)

print("Loading Argument parser...")
time.sleep(2)

parser = argparse.ArgumentParser(
    description="Puzzle solver  v1 by UFODIA: A tool to generate and search Bitcoin private keys.",
    epilog="Example: Puzzle.exe -k 20000000000000000:3ffffffffffffffff -a 13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so -s 2 10 -f puzzle66.txt",
    formatter_class=argparse.RawDescriptionHelpFormatter)

parser.add_argument("-k", "--keyspace", type=valid_hex_range, help="Specify the range of hex values as start_hex:end_hex.")
parser.add_argument("-a", "--address", type=str, required=True, help="Specify the target Bitcoin address.")
parser.add_argument("-f", "--file", type=str, default="find.txt", help="Specify the output file name for storing found keys. Default is 'find.txt'.")
parser.add_argument("-s", "--scan", nargs='*', default=[0], help="Specify the mode of operation and optionally the number of keys for hybrid mode.0 For sequential search, 1 for random search, 2 for hybrid search. Additional arg: number of keys for hybrid mode (in millions).")
parser.add_argument("-t", "--threads", type=int, default=4, help="Specify the number of threads to use (default is 4).")

args = parser.parse_args()

print("Loading Kernel...")
time.sleep(2)

start_hex, end_hex = args.keyspace
target_address = args.address
output_file = os.path.expanduser(f'~/Desktop/{args.file}')
scan_mode = int(args.scan[0])
scan_count = int(args.scan[1]) * 1000000 if len(args.scan) > 1 else 0
threads_count = args.threads

# Descriptive string for the scan mode
scan_str = 'Sequential' if scan_mode == 0 else 'Random' if scan_mode == 1 else f'Hybrid (Base hex changes every {scan_count//1000000}M hexes)'

print(f"\nUFODIA KEYS v1.0\n"
      f"https://millionmac.com\n"
      f"-------------------\n"
      f"Target BTC Address  : {target_address:<}\n"
      f"Hex Range           : {start_hex} - {end_hex}\n"
      f"Scan Mode           : {scan_str:<}\n"
      f"Threads             : {threads_count}\n"
      f"Save to             : {output_file:<}\n")

print("Scanning starts...")
time.sleep(2)

start_time = time.perf_counter()
hex_count = 0
start_range = int(start_hex, 16)
end_range = int(end_hex, 16)
current_range = start_range
change_count = 0  # Count for the number of changes in hybrid mode
results = []

# Function to process a chunk of the range
def process_chunk(start_range, end_range):
    local_results = []
    local_hex_count = 0
    local_current_range = start_range

    while local_current_range <= end_range:
        if scan_mode == 0:  # Sequential scan
            i = local_current_range
            local_current_range += 1
        elif scan_mode == 1:  # Random scan
            i = random.randint(start_range, end_range)
        elif scan_mode == 2:  # Hybrid scan
            if local_hex_count % scan_count == 0 or local_current_range > end_range:
                local_current_range = random.randint(start_range, end_range)
                change_count += 1
            i = local_current_range
            local_current_range += 1
            if local_current_range > end_range:
                continue

        priv_key_hex = format(i, 'x').zfill(64)
        key = Key.from_hex(priv_key_hex)
        address = key.address

        local_hex_count += 1

        if address == target_address:
            local_results.append(f'Private Key: {priv_key_hex}, Address: {address}')

        if local_hex_count % 20000 == 0:
            elapsed_time = time.perf_counter() - start_time
            elapsed_time = elapsed_time if elapsed_time > 0 else 1
            formatted_time = f'{int(elapsed_time // 3600)}:{int((elapsed_time % 3600) // 60):02d}:{int(elapsed_time % 60):02d}'
            formatted_hex_count = f'{local_hex_count:,}'.replace(',', '.')
            keys_per_second = local_hex_count / elapsed_time
            formatted_kps = format_keys_per_second(keys_per_second)
            change_count_str = f'R= {int(local_hex_count/scan_count)}' if scan_mode == 2 else ''
            display_key_hex = priv_key_hex.lstrip('0')
            display_key_hex = display_key_hex if display_key_hex else '0'
            print(f'\r{change_count_str} [Scanned {formatted_hex_count} keys in {formatted_time}] [{formatted_kps} Keys/s.] [Current Hex: {display_key_hex}]', end='')

    return local_results

def format_keys_per_second(kps):
    if kps < 1e3:
        return f"{kps:.2f}"
    elif kps < 1e6:
        return f"{kps/1e3:.2f}K"
    elif kps < 1e9:
        return f"{kps/1e6:.2f}M"
    else:
        return f"{kps/1e9:.2f}B"

# Split the range into chunks
range_step = (end_range - start_range + 1) // threads_count
chunks = [(start_range + i * range_step, start_range + (i + 1) * range_step - 1) for i in range(threads_count)]
chunks[-1] = (chunks[-1][0], end_range)  # Make sure the last chunk ends at end_range

# Use ThreadPoolExecutor to process the chunks in parallel
with ThreadPoolExecutor(max_workers=threads_count) as executor:
    futures = [executor.submit(process_chunk, chunk_start, chunk_end) for chunk_start, chunk_end in chunks]
    
    for future in as_completed(futures):
        results.extend(future.result())
    
# Write the results to the output file
if results:
    with open(output_file, 'a') as f:
        f.writelines(result + '\n' for result in results)

print("\nSuccessfully finished.")
