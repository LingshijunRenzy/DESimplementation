import os

# Define the filename
filename = f"randomdata.txt"

# Calculate how many random bytes we need to generate 5MB of hex text
# Each byte becomes 2 hex chars, so we need 5MB/2 = 2.5MB of bytes
size_bytes = 5 * 1024 * 1024 // 2

# Generate random bytes and convert to hexadecimal string
random_hex = os.urandom(size_bytes).hex()

# Write the data to the file
with open(filename, 'w') as f:
    f.write(random_hex)

print(f"Created file {filename} with 5MB of random hexadecimal data")