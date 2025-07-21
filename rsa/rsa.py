# imports
import time
import math
import random
import subprocess
import re
import pandas as pd
import matplotlib.pyplot as plt
import os

def is_prime(n, k=20):
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as d * 2^r
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Run Miller-Rabin test k times
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """Generate a prime number with the specified bit length"""
    while True:
        # Generate an odd number with the desired bit length
        candidate = random.getrandbits(bits)
        # Ensure it's odd and has the correct bit length
        candidate |= (1 << bits - 1) | 1
        
        if is_prime(candidate):
            return candidate

def rsa_encrypt(n, e, msg):
    """Encrypt a message using the public modulus n and public exponent e"""
    encrypted = []
    for char in msg:
        m = ord(char)  # ASCII value of character
        if m >= n:  # Check if m < n
            raise ValueError(f"Character '{char}' (ASCII {m}) is too large for modulus {n}")
        c = pow(m, e, n)  # RSA encryption: c = m^e mod n
        encrypted.append(str(c))
    return ','.join(encrypted)

def rsa_decrypt(n, d, ciphertext):
    """Decrypt an encrypted message using the public modulus n and private exponent d"""
    decrypted_chars = []
    for c_str in ciphertext.split(','):
        c = int(c_str)
        m = pow(c, d, n)  # RSA decryption: m = c^d mod n
        if 0 <= m <= 0x10FFFF:
            decrypted_chars.append(chr(m))
        else:
            return f"ERR: Invalid plaintext value: {m}"
    return ''.join(decrypted_chars)

def factorize_with_yafu(n):
    """
    Faktorisierung mit YAFU (C-implementiert)
    Parst die Ausgabe und gibt eine Liste von Faktoren zurück
    """
    try:
        # YAFU aufrufen (ohne Timeout)
        result = subprocess.run(
            ['yafu', f'factor({n})'],
            capture_output=True,
            text=True
        )
        
        # Debug: Zeige YAFU Output für Debugging
        print(f"YAFU stdout:\n{result.stdout}")
        print(f"YAFU stderr:\n{result.stderr}")
        print(f"YAFU returncode: {result.returncode}")
        
        if result.returncode != 0:
            return None
        
        # Parse YAFU output für Faktoren
        factors = []
        lines = result.stdout.split('\n')
        
        # Suche nach Faktoren in der Ausgabe
        for line in lines:
            line = line.strip()
            
            # YAFU gibt Faktoren in verschiedenen Formaten aus
            # Beispiel: "P12 = 1234567891011"
            # Oder: "ans = 1234567891011 * 9876543210987"
            
            # Suche nach P-Faktoren (Primfaktoren)
            prime_match = re.search(r'P\d+\s*=\s*(\d+)', line)
            if prime_match:
                factors.append(int(prime_match.group(1)))
                continue
            
            # Suche nach C-Faktoren (Composite faktoren)
            composite_match = re.search(r'C\d+\s*=\s*(\d+)', line)
            if composite_match:
                factors.append(int(composite_match.group(1)))
                continue
            
            # Suche nach ans = faktor1 * faktor2 * ...
            ans_match = re.search(r'ans\s*=\s*(.+)', line)
            if ans_match:
                factors_str = ans_match.group(1)
                # Split bei * und parse alle Faktoren
                for factor_str in factors_str.split('*'):
                    factor_str = factor_str.strip()
                    if factor_str.isdigit():
                        factors.append(int(factor_str))
                continue
                
            # Suche nach direkten Zahlen in Faktor-Zeilen
            # Manchmal gibt YAFU einfach die Faktoren aus
            if line.isdigit() and len(line) > 5:  # Nur große Zahlen
                factors.append(int(line))
        
        # Entferne Duplikate und sortiere
        factors = sorted(list(set(factors)))
        print(f"Parsed factors: {factors}")
        
        # Verifikation: Produkt der Faktoren sollte n ergeben
        if factors and len(factors) >= 2:
            product = 1
            for factor in factors:
                product *= factor
            if product == n:
                return factors
        
        # Fallback: Wenn Parsing fehlschlägt, versuche einfache Regex
        # Suche nach allen großen Zahlen in der Ausgabe
        all_numbers = re.findall(r'\b\d{10,}\b', result.stdout)
        if all_numbers:
            factors = [int(num) for num in all_numbers if int(num) > 1 and int(num) != n]
            print(f"Fallback factors found: {factors}")
            # Finde die zwei Faktoren, die multipliziert n ergeben
            for i in range(len(factors)):
                for j in range(i+1, len(factors)):
                    if factors[i] * factors[j] == n:
                        return [factors[i], factors[j]]
        
        return None
        
    except Exception as e:
        print(f"YAFU error: {e}")
        return None

def rsa_force_decrypt(n, e, ciphertext):
    """
    Brute-force attack using YAFU for factorization
    """
    start_time = time.time()
    
    print(f"Using YAFU for factorization of n = {n}")
    
    try:
        # Use YAFU for factorization
        factors = factorize_with_yafu(n)
        
        if not factors:
            elapsed = time.time() - start_time
            return f"ERR: Factorization failed after {elapsed:.2f} seconds"
        
        # Find the two prime factors
        if len(factors) == 2 and all(is_prime(f) for f in factors):
            p, q = factors
        else:
            # If we get multiple factors, try to find the two primes
            prime_factors = [f for f in factors if is_prime(f)]
            if len(prime_factors) >= 2:
                p, q = prime_factors[0], prime_factors[1]
                # Verify that p*q gives us n (or a factor of n)
                if p * q != n:
                    # Try to find the correct pair
                    for i in range(len(prime_factors)):
                        for j in range(i+1, len(prime_factors)):
                            if prime_factors[i] * prime_factors[j] == n:
                                p, q = prime_factors[i], prime_factors[j]
                                break
                        else:
                            continue
                        break
            else:
                elapsed = time.time() - start_time
                return f"ERR: Could not find two prime factors after {elapsed:.2f} seconds"
        
        print(f"Factorization successful: p = {p}, q = {q}")
        
        # Verify factorization
        if p * q != n:
            return f"ERR: Factorization verification failed: {p} * {q} = {p*q} != {n}"
        
        d = calc_private_key(p, q, e)
        if d is None:
            return "ERR: No inverse d found"

        decrypted_chars = []
        for c_str in ciphertext.split(','):
            c = int(c_str)
            m = pow(c, d, n)
            if 0 <= m <= 0x10FFFF:
                decrypted_chars.append(chr(m))
            else:
                return f"ERR: Invalid plaintext value: {m}"
        return ''.join(decrypted_chars)
        
    except Exception as ex:
        elapsed = time.time() - start_time
        return f"ERR: Factorization failed with exception after {elapsed:.2f} seconds: {str(ex)}"

def gcd(a, b):
    """Calculate greatest common divisor using Euclidean algorithm"""
    while b:
        a, b = b, a % b
    return a

def calc_private_key(p, q, e):
    """Efficient computation of the private exponent d using the extended Euclidean algorithm"""
    def extended_gcd(a, b):
        if b == 0:
            return a, 1, 0
        else:
            g, x, y = extended_gcd(b, a % b)
            return g, y, x - (a // b) * y

    phi = (p - 1) * (q - 1)
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        print("ERR: e and phi(n) are not coprime")
        return None
    else:
        return x % phi  # Ensure d is positive

def convert_time(seconds):
    """Method for intelligibly displaying runtimes"""
    seconds = round(seconds, 2)
    
    if seconds < 60:
        return f"{seconds:.2f} seconds"

    minutes = int(seconds // 60)
    remaining_seconds = round(seconds % 60, 2)

    if seconds < 3600:
        return f"{minutes}min {remaining_seconds:.2f}sec"

    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    remaining_seconds = round(seconds % 60, 2)
    
    if seconds < 86400:
        return f"{hours}h {minutes}min {remaining_seconds:.2f}sec"

    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    
    if seconds < 604800:
        return f"{days}d {hours}h {minutes}min"

    weeks = int(seconds // 604800)
    days = int((seconds % 604800) // 86400)
    return f"{weeks}w {days}d {hours}h"

def test_different_key_sizes(start_script_time, time_limit_minutes):
    # Bit lengths to test, defined as a range
    start_bits = 8
    end_bits = 500 # This is now the theoretical maximum
    step_bits = 8
    bit_lengths = range(start_bits, end_bits + 1, step_bits)
    
    # Message to encrypt
    msg = "This is a secret Message!"
    e = 65537
    
    # --- Write results to CSV ---
    output_file = 'rsa/rsa_summary.csv'  # Path within the rsa subdirectory
    
    print(f"\nWriting results to {output_file}")
    
    # Write the header for the summary file
    with open(output_file, 'w', newline='') as csvfile:
        csvfile.write("Bit_Length,Modulus_n,Prime_p,Prime_q,Encryption_Time,Legit_Decryption_Time,Forced_Decryption_Time\n")

    print("Comparison of different key sizes (using YAFU):")
    
    for bits in bit_lengths:
        # --- TIME CHECK ---
        elapsed_seconds = time.time() - start_script_time
        if elapsed_seconds > time_limit_minutes * 60:
            print(f"\nTime limit of {time_limit_minutes} minute(s) reached. Finalizing results.")
            break
        # --- END TIME CHECK ---
        
        try:
            # Generate prime numbers
            print(f"Generating {bits}-bit primes...")
            p = generate_prime(bits)
            q = generate_prime(bits)
            while q == p:  # Ensure p != q
                q = generate_prime(bits)
            
            n = p * q
            print(f"p = {p}")
            print(f"q = {q}")
            print(f"n = {n} (approx. {n.bit_length()} bits)")
            
            # Calculate private key
            d = calc_private_key(p, q, e)
            if d is None:
                print("Error calculating private key")
                continue
            
            # Encryption
            start_enc = time.time()
            ciphertext = rsa_encrypt(n, e, msg)
            encryption_time = time.time() - start_enc
            print(f"Message encrypted: {len(ciphertext)} characters in {convert_time(encryption_time)}")
            
            # Legitimate decryption
            start_dec = time.time()
            decrypted = rsa_decrypt(n, d, ciphertext)
            legit_time = time.time() - start_dec
            print(f"Legitimate decryption: {convert_time(legit_time)}")
            print(f"✓ Decrypted message: '{decrypted}'")
            
            # Verify that decryption was correct
            if decrypted == msg:
                print("✓ Legitimate decryption: CORRECT")
            else:
                print("✗ Legitimate decryption: INCORRECT")
                continue
            
            # Brute-force attack
            print(f"\nStarting brute-force attack with YAFU...")
            start_attack = time.time()
            result = rsa_force_decrypt(n, e, ciphertext)
            attack_time = time.time() - start_attack
            
            if result.startswith("ERR"):
                print(f"Attack aborted after {convert_time(attack_time)}")
                print(f"✗ Brute-force attack: FAILED - {result}")
            else:
                print(f"Attack successful in {convert_time(attack_time)}")
                print(f"✓ Message decrypted by brute-force: '{result}'")
                
                # Verify brute-force attack
                if result == msg:
                    print("✓ Brute-force attack: CORRECT\n")
                else:
                    print("✗ Brute-force attack: INCORRECT\n")
            
            # Append the results to the summary file
            with open(output_file, 'a', newline='') as csvfile:
                csvfile.write(f"{bits*2},{n},{p},{q},{encryption_time},{legit_time},{attack_time}\n")
                
        except Exception as ex:
            print(f"Error for {bits*2}-bit key: {ex}")
        
        print("-" * 50)

def plot_results(csv_path):
    """Reads the CSV data and plots the decryption time comparison."""
    print(f"\nGenerating plots from {csv_path}...")
    try:
        df = pd.read_csv(csv_path)
        
        # --- PLOT 1: LINEAR SCALE ---
        plt.figure(figsize=(12, 7))
        plt.plot(df['Bit_Length'], df['Legit_Decryption_Time'], label='Legitimate Decryption', color='blue')
        plt.plot(df['Bit_Length'], df['Forced_Decryption_Time'], label='Forced Decryption (Attack)', color='purple')
        
        plt.title('RSA Decryption Time vs. Key Size (Linear Scale)', fontsize=16)
        plt.xlabel('Key Size (bits)', fontsize=12)
        plt.ylabel('Time (seconds)', fontsize=12)
        plt.legend()
        plt.grid(True, which='both', linestyle='--', linewidth=0.5)
        
        output_path_linear = os.path.join(os.path.dirname(csv_path), "rsa_plot_runtime_lin.png")
        plt.savefig(output_path_linear)
        print(f"Plot saved to {output_path_linear}")
        plt.close()

        # --- PLOT 2: LOGARITHMIC SCALE ---
        plt.figure(figsize=(12, 7))
        plt.plot(df['Bit_Length'], df['Legit_Decryption_Time'], label='Legitimate Decryption', color='blue')
        plt.plot(df['Bit_Length'], df['Forced_Decryption_Time'], label='Forced Decryption (Attack)', color='purple')
        
        plt.title('RSA Decryption Time vs. Key Size (Logarithmic Scale)', fontsize=16)
        plt.xlabel('Key Size (bits)', fontsize=12)
        plt.ylabel('Time (seconds)', fontsize=12)
        plt.legend()
        plt.grid(True, which='both', linestyle='--', linewidth=0.5)
        plt.yscale('log')
        
        output_path_log = os.path.join(os.path.dirname(csv_path), "rsa_plot_runtime_log.png")
        plt.savefig(output_path_log)
        print(f"Plot saved to {output_path_log}")
        plt.close()

    except Exception as e:
        print(f"Failed to generate plot: {e}")

def main():
    """Main method"""
    while True:
        try:
            runtime_input = input("Please enter the time limit for the RSA script in minutes: ")
            RUNTIME_LIMIT_MINUTES = float(runtime_input)
            if RUNTIME_LIMIT_MINUTES > 0:
                break
            else:
                print("Please enter a positive number.")
        except ValueError:
            print("Invalid input. Please enter a number.")
            
    script_start_time = time.time()

    print("=" * 60)
    print(f"RSA SCRIPT HAS STARTED | TIME LIMIT: {RUNTIME_LIMIT_MINUTES} MINUTE(S)")
    print("=" * 60)

    # Test different key sizes
    test_different_key_sizes(script_start_time, RUNTIME_LIMIT_MINUTES)

    # After testing is done, plot the results
    output_file = 'rsa/rsa_summary.csv'
    plot_results(output_file)

if __name__ == "__main__":
    main()