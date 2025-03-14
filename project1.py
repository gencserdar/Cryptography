import math
import random
import time

# Miller-Rabin primality test
def miller_rabin(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as d*2^r
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    def is_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(r):
            if pow(a, 2**i * d, n) == n - 1:
                return False
        return True

    for _ in range(k):
        a = random.randint(2, n - 2)
        if is_composite(a):
            return False
    return True

# Optimized Sieve of Eratosthenes for large ranges
def sieve_of_eratosthenes(limit):
    primes = []
    sieve = {}
    for num in range(2, int(math.sqrt(limit)) + 1):
        if num not in sieve:
            primes.append(num)
            for multiple in range(num * num, limit + 1, num):
                sieve[multiple] = True
    for num in range(int(math.sqrt(limit)) + 1, limit + 1):
        if num not in sieve:
            primes.append(num)
    return primes

def sieve_of_atkin(limit):
    if limit < 2:
        return []

    sieve = [False] * (limit + 1)
    primes = []

    sqrt_limit = int(math.sqrt(limit)) + 1

    # Mark sieve[n] as True for specific modular conditions
    for x in range(1, sqrt_limit):
        for y in range(1, sqrt_limit):
            n = 4 * x**2 + y**2
            if n <= limit and (n % 12 == 1 or n % 12 == 5):
                sieve[n] = not sieve[n]
            n = 3 * x**2 + y**2
            if n <= limit and n % 12 == 7:
                sieve[n] = not sieve[n]
            n = 3 * x**2 - y**2
            if x > y and n <= limit and n % 12 == 11:
                sieve[n] = not sieve[n]

    # Mark multiples of squares of primes as non-prime
    for i in range(5, sqrt_limit):
        if sieve[i]:
            for j in range(i * i, limit + 1, i * i):
                sieve[j] = False

    # Collect all primes
    primes.extend([2, 3])  # Add small primes manually
    primes.extend([i for i in range(5, limit + 1) if sieve[i]])

    return primes


# Main program
def main():
    while True: 
        print("Prime Number Testing Algorithms")
        print("1. Miller-Rabin Test")
        print("2. Sieve of Eratosthenes")
        print("3. Sieve of Atkin")
        print("0. Quit")
        choice = int(input("Select option: "))

        if choice == 1:
            n = int(input("Enter the number to test: "))
            k = int(input("Enter the number of iterations for accuracy (e.g., 5): "))
            start = time.perf_counter()
            result = miller_rabin(n, k)
            end = time.perf_counter()
            print(f"Miller-Rabin Test: {'Prime' if result else 'Not Prime'}")
            print(f"Time Taken: {end - start:.6f} seconds")

        elif choice == 2:
            limit = int(input("Enter the limit to find all primes up to: "))
            start = time.perf_counter()
            primes = sieve_of_eratosthenes(limit)
            end = time.perf_counter()
            print(f"Number of primes up to {limit}: {len(primes)}")
            print(f"Time Taken: {end - start:.6f} seconds")

        elif choice == 3:
            limit = int(input("Enter the limit to find all primes up to: "))
            start = time.perf_counter()
            primes = list(sieve_of_atkin(limit))
            end = time.perf_counter()
            print(f"Number of primes up to {limit}: {len(primes)}")
            print(f"Time Taken: {end - start:.6f} seconds")
        
        elif choice == 0:
            print("Terminating the program...")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
