'''
    @author Matteo Gianvenuti https://github.com/mqtth3w
    @license MIT License
'''

import itertools
import random
import string

name = ["Vaorb"]
surname = ["Gakol"]
fav_films = ["Inception", "Matrix", "Avatar"]
fav_names = ["Alice", "Bob", "Charlie"]
fav_colors = ["Rosso"]
fav_numbers = ["4", "45"]
fav_date = ["13/03/2020", "7 May"]
fav_animals = ["tiger"]

def gen_combinations(*lists):
    print("Generating combinations...")
    combinations = list(itertools.product(*lists))
    print(f"Generated {len(combinations)} combinations")
    return combinations

def custom_password(combo, min_len=8, max_len=12, num_special_chars=None, num_digits=None):
    base_password = ''.join(combo)
    password_length = random.randint(min_len, max_len)
    if num_special_chars is not None:
        base_password += ''.join(random.choices(string.punctuation, k=num_special_chars))
    if num_digits is not None:
        base_password += ''.join(random.choices(string.digits, k=num_digits))
    if len(base_password) < password_length:
        additional_chars = password_length - len(base_password)
        additional_chars_str = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=additional_chars))
        base_password += additional_chars_str
    return base_password

def meets_criteria(password, min_len, max_len, num_special_chars, num_digits):
    if len(password) < min_len or len(password) > max_len:
        return False
    if num_special_chars is not None and sum(1 for c in password if c in string.punctuation) < num_special_chars:
        return False
    if num_digits is not None and sum(1 for c in password if c.isdigit()) < num_digits:
        return False
    return True

def generate_passwords(combinations, min_len=8, max_len=12, num_special_chars=None, num_digits=None):
    print("Generating passwords...")
    passwords = []
    for combo in combinations:
        pwd = custom_password(combo, min_len, max_len, num_special_chars, num_digits)
        if meets_criteria(pwd, min_len, max_len, num_special_chars, num_digits):
            passwords.append(pwd)
    print(f"Generated {len(passwords)} passwords")
    return passwords

# For testing, use a subset of lists to reduce the number of combinations
# Comment this line to use all combinations
#all_combinations = gen_combinations(fav_films, fav_names)

# Uncomment this line to use all combinations
all_combinations = gen_combinations(name, surname, fav_films, fav_names, fav_colors, fav_numbers, fav_date, fav_animals)

# Generate and print passwords with specific criteria
print("With criteria:")
some_passwords = generate_passwords(all_combinations, min_len=8, max_len=16, num_special_chars=2, num_digits=2)
for pwd in some_passwords:
    print(pwd)

# Generate and print passwords without specific criteria
print("Without criteria:")
all_passwords = generate_passwords(all_combinations)
for pwd in all_passwords:
    print(pwd)
