# imports
import time
import random
import numpy as np
import fpylll
from typing import Tuple, List, Optional
import csv
import pandas as pd
import matplotlib.pyplot as plt
import os

def convert_time(seconds):
    # Converts seconds into a more readable time format
    if seconds < 1:
        return f"{seconds * 1000:.2f} ms"
    elif seconds < 60:
        return f"{seconds:.2f} s"
    else:
        minutes = int(seconds / 60)
        secs = seconds % 60
        return f"{minutes} min {secs:.2f} s"

def generate_keys(n: int) -> Tuple[np.ndarray, np.ndarray]:
    # Generates a pair of lattice bases
    private_basis = np.eye(n, dtype=int)
    public_basis = private_basis.copy()
    num_transformations = n * n
    for _ in range(num_transformations):
        i, j = random.sample(range(n), 2)
        factor = random.randint(-n, n)
        if factor != 0:
            public_basis[i] = public_basis[i] + factor * public_basis[j]
            
    return private_basis, public_basis

def encrypt(message: str, n: int, noise_level: float) -> Tuple[List[List[float]], int]:
    # Encrypts a message
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    original_bit_length = len(binary_message)
    
    while len(binary_message) % n != 0:
        binary_message += '0'
        
    chunks = [binary_message[i:i+n] for i in range(0, len(binary_message), n)]
    
    encrypted_vectors = []
    for chunk in chunks:
        lattice_point = np.array([int(bit) for bit in chunk], dtype=float)
        noise = np.random.uniform(-noise_level, noise_level, n)
        noisy_point = lattice_point + noise
        encrypted_vectors.append(noisy_point.tolist())
        
    return encrypted_vectors, original_bit_length

def decrypt(solved_vectors: List[List[int]], n: int, original_bit_length: int) -> str:
    # Decrypts a message
    binary_message = ""
    for vector in solved_vectors:
        if not vector:
            binary_message += '?' * n
            continue
        for coord in vector:
            bit = int(round(coord)) % 2
            binary_message += str(bit)
            
    binary_message = binary_message[:original_bit_length]
    
    message = ""
    for i in range(0, len(binary_message), 8):
        byte = binary_message[i:i+8]
        if len(byte) == 8:
            try:
                char_code = int(byte, 2)
                if 32 <= char_code <= 126:
                    message += chr(char_code)
                else:
                    message += ''
            except ValueError:
                message += '?'
                
    return message

def solve_cvp_good_basis(target_vectors: List[List[float]]) -> List[List[int]]:
    # Solves the CVP with a good basis
    solved_vectors = []
    for v in target_vectors:
        solved_vectors.append([int(round(c)) for c in v])
    return solved_vectors

def solve_cvp_bad_basis(basis: np.ndarray, target_vectors: List[List[float]]) -> List[List[int]]:
    # Solves the CVP with a bad basis (LLL reduction)
    solved_vectors = []
    SCALE = 10000
    
    try:
        scaled_basis_int = (basis * SCALE).astype(np.int64).tolist()
        fpylll_basis = fpylll.IntegerMatrix.from_matrix(scaled_basis_int)
        fpylll.LLL.reduction(fpylll_basis)

        for v in target_vectors:
            target_scaled_int = [int(round(c * SCALE)) for c in v]
            closest_scaled_vector = fpylll.CVP.closest_vector(fpylll_basis, target_scaled_int)
            closest_vector = [int(round(c / SCALE)) for c in closest_scaled_vector]
            solved_vectors.append(closest_vector)
            
        return solved_vectors

    except Exception as e:
        n = basis.shape[0]
        print(f"ERROR: CVP solver failed for dimension {n}: {e}")
        return [[0] * n for _ in target_vectors]

def measure_success(original_message: str, decrypted_message: str) -> float:
    # Measures the success rate of decryption
    if not original_message or not decrypted_message:
        return 0.0
    correct = sum(1 for i in range(min(len(original_message), len(decrypted_message))) if original_message[i] == decrypted_message[i])
    return (correct / len(original_message)) * 100

def run_single_trial(n: int, message: str, noise_level: float):
    # Performs a single encryption/decryption trial
    _, public_basis = generate_keys(n)
    
    start_time_encrypt = time.time()
    encrypted_vectors, original_bit_length = encrypt(message, n, noise_level)
    time_encrypt = time.time() - start_time_encrypt
    
    start_time_good = time.time()
    good_solved_vectors = solve_cvp_good_basis(encrypted_vectors)
    time_good = time.time() - start_time_good
    good_decrypted_message = decrypt(good_solved_vectors, n, original_bit_length)
    success_good = measure_success(message, good_decrypted_message)
    
    start_time_bad = time.time()
    bad_solved_vectors = solve_cvp_bad_basis(public_basis, encrypted_vectors)
    time_bad = time.time() - start_time_bad
    bad_decrypted_message = decrypt(bad_solved_vectors, n, original_bit_length)
    success_bad = measure_success(message, bad_decrypted_message)

    return {
        'time_encrypt': time_encrypt, 
        'time_good': time_good, 
        'time_bad': time_bad, 
        'success_good': success_good, 
        'success_bad': success_bad
    }

def main():
    # Main function for accuracy analysis
    random.seed(42)
    np.random.seed(42)

    while True:
        try:
            runtime_input = input("Please enter the runtime limit for the script in minutes: ")
            RUNTIME_LIMIT_MINUTES = float(runtime_input)
            if RUNTIME_LIMIT_MINUTES > 0:
                break
            else:
                print("Invalid input. Please enter a positive number.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    while True:
        try:
            trials_input = input("Please enter the number of trials per dimension: ")
            TRIALS_PER_DIMENSION = int(trials_input)
            if TRIALS_PER_DIMENSION > 0:
                break
            else:
                print("Invalid input. Please enter a positive integer.")
        except ValueError:
            print("Invalid input. Please enter an integer.")

    script_start_time = time.time()

    message = "This is a secret Message!"
    noise_level = 0.25 
    
    min_dim = 2
    max_dim = 500
    
    print("=" * 60)
    print("Lattice-based Cryptography Scaling Analysis - EXPERIMENT 2: ACCURACY")
    print(f"Message: '{message}'")
    print(f"Noise Level: {noise_level}")
    print(f"Test Dimensions: {min_dim} to {max_dim} ({TRIALS_PER_DIMENSION} trials per dimension)")
    print(f"TIME LIMIT: {RUNTIME_LIMIT_MINUTES} MINUTE(S)")
    print("=" * 60)
    
    results = []
    for n in range(min_dim, max_dim + 1):
        elapsed_seconds = time.time() - script_start_time
        if elapsed_seconds > RUNTIME_LIMIT_MINUTES * 60:
            print(f"\nTime limit of {RUNTIME_LIMIT_MINUTES} minute(s) reached. Finalizing results.")
            break

        total_time_encrypt, total_time_good, total_time_bad = 0, 0, 0
        total_success_good, total_success_bad = 0, 0

        print(f"\n--- Test Dimension {n} ---")
        for i in range(TRIALS_PER_DIMENSION):
            trial_results = run_single_trial(n, message, noise_level)
            total_time_encrypt += trial_results['time_encrypt']
            total_time_good += trial_results['time_good']
            total_time_bad += trial_results['time_bad']
            total_success_good += trial_results['success_good']
            total_success_bad += trial_results['success_bad']
            print(f"  Trial {i + 1}/{TRIALS_PER_DIMENSION} completed...", end='\r')
        
        avg_results = {
            'dimension': n,
            'time_encrypt': total_time_encrypt / TRIALS_PER_DIMENSION,
            'time_good': total_time_good / TRIALS_PER_DIMENSION,
            'success_good': total_success_good / TRIALS_PER_DIMENSION,
            'time_bad': total_time_bad / TRIALS_PER_DIMENSION,
            'success_bad': total_success_bad / TRIALS_PER_DIMENSION
        }
        results.append(avg_results)
        
        print(f"\n  Avg. Encryption Time: {convert_time(avg_results['time_encrypt'])}")
        print(f"  Avg. Decryption Good Basis: {avg_results['success_good']:.1f}% success in {convert_time(avg_results['time_good'])}")
        print(f"  Avg. Decryption Bad Basis:  {avg_results['success_bad']:.1f}% success in {convert_time(avg_results['time_bad'])}")

    csv_file = "lattice/lattice_summary_accuracy.csv"
    csv_columns = ['dimension', 'avg_Encrypt_Time', 'avg_Decrypt_Time_Good', 'avg_Success_Good', 'avg_Decrypt_Time_Bad', 'avg_Success_Bad']
    
    try:
        with open(csv_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(csv_columns)
            for res in results:
                writer.writerow([res['dimension'], res['time_encrypt'], res['time_good'], res['success_good'], res['time_bad'], res['success_bad']])
        print(f"\nResults summary written to {csv_file}")
    except IOError:
        print(f"ERROR: Writing to {csv_file} failed")
        
    plot_results(csv_file)

def plot_results(csv_path):
    # Plots the decryption success rate
    print(f"\nGenerating plot from {csv_path}...")
    try:
        df = pd.read_csv(csv_path)
        
        plt.figure(figsize=(12, 7))
        plt.plot(df['dimension'], df['avg_Success_Good'], label='Success Good Base (Private Key)', color='green')
        plt.plot(df['dimension'], df['avg_Success_Bad'], label='Success Bad Base (Public Key)', color='red')
        
        plt.title('Decryption Success Rate vs. Lattice Dimension', fontsize=16)
        plt.xlabel('Lattice Dimension (n)', fontsize=12)
        plt.ylabel('Average Success Rate (%)', fontsize=12)
        plt.legend()
        plt.grid(True, which='both', linestyle='--', linewidth=0.5)
        plt.ylim(-5, 105)
        
        output_path = os.path.join(os.path.dirname(csv_path), "lattice_acc_plot.png")
        plt.savefig(output_path)
        print(f"Plot saved at {output_path}")
        plt.close()

    except Exception as e:
        print(f"ERROR: Plot creation failed: {e}")

if __name__ == "__main__":
    main()