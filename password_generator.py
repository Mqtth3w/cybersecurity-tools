'''
    @author Matteo Gianvenuti https://github.com/mqtth3w
    @license GPL-3.0
'''

import itertools

all_items = [ #user data as name, favorites stuff etc
    "Vaorb", "Gakol", "Inception", "Matrix", "Avatar",
    "Alice", "Bob", "Charlie", "Red", "4", "45",
    "13/03/2020", "7 May", "tiger"
]

def gen_combinations(items, min_len=1, max_len=None):
    if max_len is None:
        max_len = len(items)
    for r in range(min_len, max_len + 1):
        for combo in itertools.combinations(items, r):
            yield from itertools.permutations(combo)

def generate_passwords(combinations):
    for combo in combinations:
        yield ''.join(combo)

#len in terms of words
min_length = 2
max_length = 5

combinations_generator = gen_combinations(all_items, min_len=min_length, max_len=max_length)
passwords_generator = generate_passwords(combinations_generator)

'''
with open('passwords.txt', 'w', encoding='utf-8') as f:
    for pwd in passwords_generator:
        f.write(pwd + '\n')
'''

#'''
count = 0
for pwd in passwords_generator:
    count += 1
    print(pwd)
print(count)
#'''

