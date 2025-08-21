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
    # Checkt, ob eine Zahl eine Primzahl ist
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
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
    # Erzeugt eine Primzahl mit der angegebenen Bitlänge
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << bits - 1) | 1
        
        if is_prime(candidate):
            return candidate

def rsa_encrypt(n, e, msg):
    # Verschlüsselt eine Nachricht nach RSA
    encrypted = []
    for char in msg:
        m = ord(char)
        if m >= n:
            raise ValueError(f"Character '{char}' (ASCII {m}) is too large for modulus {n}")
        c = pow(m, e, n)
        encrypted.append(str(c))
    return ','.join(encrypted)

def rsa_decrypt(n, d, ciphertext):
    # Entschlüsselt eine mit RSA verschlüsselte Nachricht mittels private Key d
    decrypted_chars = []
    for c_str in ciphertext.split(','):
        c = int(c_str)
        m = pow(c, d, n)
        if 0 <= m <= 0x10FFFF:
            decrypted_chars.append(chr(m))
        else:
            return f"FEHLER: Ungültiger Klartext: {m}"
    return ''.join(decrypted_chars)

def factorize_with_yafu(n):
    # Führt die Faktorisierung mit YAFU durch
    try:
        result = subprocess.run(
            ['yafu', f'factor({n})'],
            capture_output=True,
            text=True
        )
        
        print(f"YAFU stdout:\n{result.stdout}")
        print(f"YAFU stderr:\n{result.stderr}")
        print(f"YAFU returncode: {result.returncode}")
        
        if result.returncode != 0:
            return None
        
        factors = []
        lines = result.stdout.split('\n')
        
        for line in lines:
            line = line.strip()
            
            prime_match = re.search(r'P\d+\s*=\s*(\d+)', line)
            if prime_match:
                factors.append(int(prime_match.group(1)))
                continue
            
            composite_match = re.search(r'C\d+\s*=\s*(\d+)', line)
            if composite_match:
                factors.append(int(composite_match.group(1)))
                continue
            
            ans_match = re.search(r'ans\s*=\s*(.+)', line)
            if ans_match:
                factors_str = ans_match.group(1)
                for factor_str in factors_str.split('*'):
                    factor_str = factor_str.strip()
                    if factor_str.isdigit():
                        factors.append(int(factor_str))
                continue

            if line.isdigit() and len(line) > 5:
                factors.append(int(line))
        
        print(f"Geparste Faktoren: {factors}")
        
        if factors and len(factors) >= 2:
            product = 1
            for factor in factors:
                product *= factor
            if product == n:
                return factors
        
        all_numbers = re.findall(r'\b\d{10,}\b', result.stdout)
        if all_numbers:
            factors = [int(num) for num in all_numbers if int(num) > 1 and int(num) != n]
            print(f"Fallback-Faktoren gefunden: {factors}")
            for i in range(len(factors)):
                for j in range(i+1, len(factors)):
                    if factors[i] * factors[j] == n:
                        return [factors[i], factors[j]]
        
        return None
        
    except Exception as e:
        print(f"YAFU-Fehler: {e}")
        return None

def rsa_force_decrypt(n, e, ciphertext):
    # Führt mittels Faktorisierung einen Brute-Force-Angriff auf RSA durch
    start_time = time.time()
    
    print(f"Verwende YAFU zur Faktorisierung von n = {n}")
    
    try:
        factors = factorize_with_yafu(n)
        
        if not factors:
            elapsed = time.time() - start_time
            return f"FEHLER: Faktorisierung fehlgeschlagen nach {elapsed:.2f} Sekunden"
        
        if len(factors) == 2 and all(is_prime(f) for f in factors):
            p, q = factors
        else:
            prime_factors = [f for f in factors if is_prime(f)]
            if len(prime_factors) >= 2:
                p, q = prime_factors[0], prime_factors[1]
                if p * q != n:
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
                return f"FEHLER: Konnte keine zwei Primfaktoren nach {elapsed:.2f} Sekunden finden"
        
        print(f"Faktorisierung erfolgreich: p = {p}, q = {q}")
        
        if p * q != n:
            return f"FEHLER: Faktorisierungsprüfung fehlgeschlagen: {p} * {q} = {p*q} != {n}"
        
        d = calc_private_key(p, q, e)
        if d is None:
            return "FEHLER: Kein inverser d gefunden"

        decrypted_chars = []
        for c_str in ciphertext.split(','):
            c = int(c_str)
            m = pow(c, d, n)
            if 0 <= m <= 0x10FFFF:
                decrypted_chars.append(chr(m))
            else:
                return f"FEHLER: Ungültiger Klartextwert: {m}"
        return ''.join(decrypted_chars)
        
    except Exception as ex:
        elapsed = time.time() - start_time
        return f"FEHLER: Faktorisierung fehlgeschlagen mit Ausnahme nach {elapsed:.2f} Sekunden: {str(ex)}"

def gcd(a, b):
    # Berechnet den größten gemeinsamen Teiler zweier Zahlen
    while b:
        a, b = b, a % b
    return a

def calc_private_key(p, q, e):
    # Berechnet den privaten Exponenten d
    def extended_gcd(a, b):
        if b == 0:
            return a, 1, 0
        else:
            g, x, y = extended_gcd(b, a % b)
            return g, y, x - (a // b) * y

    phi = (p - 1) * (q - 1)
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        print("FEHLER: e und phi(n) sind nicht koprim")
        return None
    else:
        return x % phi

def convert_time(seconds):
    # Konvertiert Sekunden in ein besser lesbares Zeitformat
    seconds = round(seconds, 2)
    
    if seconds < 60:
        return f"{seconds:.2f} Sekunden"

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

def test_different_key_sizes(start_script_time, time_limit_hours):
    # Testet RSA mit stetig wachsenden Schlüsselgrößen um Skalierung zu erfassen
    start_bits = 8
    end_bits = 500
    step_bits = 8
    bit_lengths = range(start_bits, end_bits + 1, step_bits)
    
    msg = "This is a secret Message!" # Zu verschlüsselnde Nachricht
    e = 65537 # Konstante für öffentlichen Exponenten
    
    output_file = 'rsa/rsa_summary.csv'
    
    print(f"\nSchreibe Ergebnisse nach {output_file}")
    
    with open(output_file, 'w', newline='') as csvfile:
        csvfile.write("Bit_Length,Modulus_n,Prime_p,Prime_q,Encryption_Time,Legit_Decryption_Time,Forced_Decryption_Time\n")

    print("Vergleich verschiedener Schlüsselgrößen (mit YAFU):")
    
    for bits in bit_lengths:
        elapsed_seconds = time.time() - start_script_time
        if elapsed_seconds > time_limit_hours * 60 * 60:
            print(f"\nZeitlimit von {time_limit_hours} Stunde(n) erreicht. Finalisiere Ergebnisse.")
            break
        
        try:
            print(f"Generiere {bits}-Bit-Primzahlen...")
            p = generate_prime(bits)
            q = generate_prime(bits)
            while q == p:
                q = generate_prime(bits)
            
            n = p * q
            print(f"p = {p}")
            print(f"q = {q}")
            print(f"n = {n} (ca. {n.bit_length()} Bits)")
            
            d = calc_private_key(p, q, e)
            if d is None:
                print("Fehler bei der Berechnung des privaten Schlüssels")
                continue
            
            start_enc = time.time()
            ciphertext = rsa_encrypt(n, e, msg)
            encryption_time = time.time() - start_enc
            print(f"Nachricht verschlüsselt: {len(ciphertext)} Zeichen in {convert_time(encryption_time)}")
            
            start_dec = time.time()
            decrypted = rsa_decrypt(n, d, ciphertext)
            legit_time = time.time() - start_dec
            print(f"Legitime Entschlüsselung: {convert_time(legit_time)}")
            print(f"Entschlüsselte Nachricht: '{decrypted}'")
            
            if decrypted == msg:
                print("Legitime Entschlüsselung: KORREKT")
            else:
                print("Legitime Entschlüsselung: FALSCH")
                continue
            
            print(f"\nStarte Brute-Force-Angriff mit YAFU...")
            start_attack = time.time()
            result = rsa_force_decrypt(n, e, ciphertext)
            attack_time = time.time() - start_attack
            
            if result.startswith("FEHLER"):
                print(f"Angriff abgebrochen nach {convert_time(attack_time)}")
                print(f"Brute-Force-Angriff: FEHLGESCHLAGEN - {result}")
            else:
                print(f"Angriff erfolgreich in {convert_time(attack_time)}")
                print(f"Nachricht entschlüsselt durch Brute-Force: '{result}'")
                
                if result == msg:
                    print("Brute-Force-Angriff: KORREKT\n")
                else:
                    print("Brute-Force-Angriff: FALSCH\n")
            
            with open(output_file, 'a', newline='') as csvfile:
                csvfile.write(f"{bits*2},{n},{p},{q},{encryption_time},{legit_time},{attack_time}\n")
                
        except Exception as ex:
            print(f"Fehler für {bits*2}-Bit-Schlüssel: {ex}")
        
        print("-" * 50)

def plot_results(csv_path):
    # Plottet die Ergebnisse der Ver- und Entschlüsselungszeiten in zwei Graphen
    print(f"\nErzeuge Plots aus {csv_path}...")
    try:
        df = pd.read_csv(csv_path)
        
        plt.figure(figsize=(12, 7))
        plt.plot(df['Bit_Length'], df['Legit_Decryption_Time'], label='Legitimate Decryption', color='blue')
        plt.plot(df['Bit_Length'], df['Forced_Decryption_Time'], label='Forced Decryption (Attack)', color='purple')
        
        plt.title('RSA-Entschlüsselungszeit vs. Schlüsselgröße (Lineare Skala)', fontsize=16)
        plt.xlabel('Schlüsselgröße (Bits)', fontsize=12)
        plt.ylabel('Zeit (Sekunden)', fontsize=12)
        plt.legend()
        plt.grid(True, which='both', linestyle='--', linewidth=0.5)
        
        output_path_linear = os.path.join(os.path.dirname(csv_path), "rsa_plot_runtime_lin.png")
        plt.savefig(output_path_linear)
        print(f"Plot gespeichert unter {output_path_linear}")
        plt.close()

        plt.figure(figsize=(12, 7))
        plt.plot(df['Bit_Length'], df['Legit_Decryption_Time'], label='Legitimate Decryption', color='blue')
        plt.plot(df['Bit_Length'], df['Forced_Decryption_Time'], label='Forced Decryption (Attack)', color='purple')
        
        plt.title('RSA-Entschlüsselungszeit vs. Schlüsselgröße (Logarithmische Skala)', fontsize=16)
        plt.xlabel('Schlüsselgröße (Bits)', fontsize=12)
        plt.ylabel('Zeit (Sekunden)', fontsize=12)
        plt.legend()
        plt.grid(True, which='both', linestyle='--', linewidth=0.5)
        plt.yscale('log')
        
        output_path_log = os.path.join(os.path.dirname(csv_path), "rsa_plot_runtime_log.png")
        plt.savefig(output_path_log)
        print(f"Plot gespeichert unter {output_path_log}")
        plt.close()

    except Exception as e:
        print(f"Fehler beim Erstellen des Plots: {e}")

def main():
    # Hauptfunktion zum Ausführen des RSA-Skripts
    while True:
        try:
            runtime_input = input("Bitte geben Sie die Laufzeitgrenze für das RSA-Skript in Stunden ein: ")
            RUNTIME_LIMIT_HOURS = float(runtime_input)
            if RUNTIME_LIMIT_HOURS > 0:
                break
            else:
                print("Bitte geben Sie eine positive Zahl ein.")
        except ValueError:
            print("Ungültige Eingabe. Bitte geben Sie eine Zahl ein.")
            
    script_start_time = time.time()

    print("=" * 60)
    print(f"RSA-SKRIPT HAT GESTARTET | LAUFZEITGRENZE: {RUNTIME_LIMIT_HOURS} STUNDE(N)")
    print("=" * 60)

    test_different_key_sizes(script_start_time, RUNTIME_LIMIT_HOURS)

    output_file = 'rsa/rsa_summary.csv'
    plot_results(output_file)

if __name__ == "__main__":
    main()