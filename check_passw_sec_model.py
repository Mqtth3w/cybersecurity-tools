from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import numpy as np

passwords = [
    "football", "monkey", "master", "shadow", "michael", "jennifer", "hunter", #0
    "buster", "thomas", "superman", "4349934", "harley", "william", "daniel", #0
    "hannah", "ranger", "hell", "123456789", "password1", "qazwsx", "1234", #0
    "dragon", "password123", "securepassword", "qwerty", "12345","randompassword", #0
    "letmein", "football123", "hello123", "iloveyou", "changeme", "qwerty123", #0
    "welcome123", "admin", "admin123", "administrator", "123456", "abc123", #0
    "passw0rd!", "password!", "Pa$$w0rd!", "Pa$$word123", "MyDog'sNameIsBuddy2023", #1
    "S3cur3P@$$w0rd!", "p@$$w0rd", "Pa$$w0rd!123", "Abc@123defGHI", "Qwerty!2345", #1
    "P@ssword789!", "Hello#123World", "MyP@ssword456", "1LoveP@ss!", "!Qwerty9876", #1
    "AbC@321def", "P@55w0rd!zZ", "123P@$$word", "987!HelloWorld", "LetMeIn@987", #1
    "abcDEF!123", "P@ss123word!", "3xAmpl3!Pa$$", "Qw3rty!789", "P@ssw0rd@321", #1
    "4567P@$$word!", "!987P@ssword", "HelloWorld!123", "P@55w0rd@!", "!Qwerty1234" #1
    "P@$$word!567", "1234AbC@!", "Pa$$word#789", "987@P@ssw0rd", "!Pa$$word432", #1
    "P@$$!567word", "321!P@ssword", "P@ssword!432", "!876P@ssword#1", "P@rtwyjrd!2", #1
    "StrongP@ssw0rd!", "MyS3cur3P@$$w0rd", "C0mp13xP@ssw0rd!", "P@ssw0rd!123", #2
    "H3ll0W0rld!", "Secur1tyP@$$", "5tr0ngP@$$w0rd", "Myp@$$word456", "C@pital!zeMe", #2
    "7est123P@$$", "P@$$w0rd!789", "L0ngP@$$w0rd!", "MyP@$$w0rd#1", "123abc!P@$$", #2
    "P@$$w0rd!QWERTY", "Strong123!", "Myp@$$w0rd!", "C@p!tal123", "123P@$$w0rd", #2
    "H!ghSecur1ty", "W3lc0m3H0me!", "P@$$w0rd!456", "MyS3cur3!", "C@pitalP@$$", #2
    "123!P@ssw0rd", "H@rd2Gu3ss!", "P@$$w0rd!XYZ", "Myp@$$123!", "C@p!tal1234", #2
    "123P@$$word!", "7h3Secr3t!", "P@$$w0rd!7890", "MyP@$$w0rd987", "C@pital!z3Me", #2
    "P@$$word!1234", "Myp@$$word!2023", "C@p!tal!ze1", "123!P@ssword", "W3lc0m3!123", #2
    "as@ss!2023", "C0mdapl3x12sd3!Pa$$", "H!gh3rdsSecur!ty!", "MyP@$$w0rd!7890", #3
    "W3lcsad0m3B@ck!Pa$$", "P@sd$$s!456!Str0ng!", "Myp@$$sd!2024?", "C@p!tals!z3_1!Pa$$", #3
    "123!P@sass!1!", "W3lc0m3as!2023!", "B3tt3asr!Pa$$was0rd!Secur3", "P@$a$!sABasC!123",
    "Myp@$$!@4as56#", "MydewfP@$egdf!15545#", "d@pdsegf!tal!tehzge3!", #3
    "C@p!taslP@$as$w0rd!", "123!P@as$$!ABC!", "W3lsac0m3!456!", "Str0ngsa3r!Pa$$w0rd!", #3
    "My$3cur3!Pa$$w0rd123", "C0mp1exP@$$w0rd!", "P@$$!9876!", "MyP@$$!12345#", "C@p!tafl!zeM3!", #3
    "123Prg$$!ABregCrg!", "W3lc0m3f!78r9#Sercur3", "N3w!Pa$d$w0rd!2023", "P@$weg$!78910",
    "Myp@sd$$98765", "Myp@$$ytk!2025!", "C@p!tal123yuk45!Pa$$", "123uyk!P@$$!123#", #3
    "C@prg!tal!zergM3!", "123!ytP@$$!ArgBC!", "W3lc0m3!yjt1234!", "Superuk!0rPa$$w0rd!", #3
    "My$ecuewrew3P@eg$$gword!", "C0mpl3esgwexP@$eg$!w0rd!", "P@$$!5rg678!", #3
    "J$@38fA!n2@K6rY4gT#dQ5fGtZ9hR1jN8", "M#9p@F!a3$N5tG7zR*dQ2sFtW8hA1jP", #4
    "L@5h#T!m8$G2kY3pZ#bR6fCtX0qA9jE", "P$@7kA!z3#L6tY4gQ#dF5bGtZ9rH1jV", #4
    "R#2n@G!d7@K3jY4gT#fD5gBtZ1hR9jM", "B$@4dA!n8#K6rY3gT#dQ5fGtZ9hR1jF", #4
    "N#8p@D!a2$N6tG5zR*dQ3sFtW7hA0jS", "K@6h#T!m9$G3kY2pZ#bR7fCtX1qA8jQ", #4
    "Q$@3kA!z6#L8tY5gQ#dF6bGtZ0rH2jE", "H#9p@F!a1$N7tG6zR*dQ1sFtW9hA3jM", #4
    "S#1n@G!d9@K4jY3gT#fD6gBtZ2hR7jP", "F$@5dA!n7#K5rY2gT#dQ4fGtZ8hR0jV", #4
    "P$@6kA!z4#L7tY2gQ#dF7bGtZ3rH5jF", "R#3n@G!d6@K9jY1gT#fD7gBtZ4hR0jQ", #4
    "N#7p@D!a3$N9tG4zR*dQ2sFtW6hA6jV", "K@5h#T!m8$G1kY6pZ#bR9fCtX3qA4jP", #4
    "Q$@2kA!z5#L9tY3gQ#dF8bGtZ6rH7jM", "B$@9dA!n1#K7rY8gT#dQ2fGtZ5hR3jS", #4
    "S#4n@G!d3@K1jY8gT#fD9gBtZ7hR5jE", "F$@7dA!n9#K8rY5gT#dQ3fGtZ0hR2jQ", #4
    "P$@8kA!z1#L5tY6gQ#dF9bGtZ8rH3jV", "R#5n@G!d2@K3jY7gT#fD1gBtZ9hR4jM", #4
    "B$@1dA!n5#K9rY2gT#dQ8fGtZ0hR6jE", "H#6p@F!a2$N8tG3zR*dQ4sFtW5hA5jS", #4
    "N#9p@D!a8$N4tG1zR*dQ5sFtW3hA7jP", "K@4h#T!m7$G5kY8pZ#bR2fCtX9qA9jQ", #4
    "S#7n@G!d4@K2jY9gT#fD2gBtZ2hR9jE", "F$@9dA!n6#K1rY4gT#dQ7fGtZ3hR1jF", #4
    "H#2p@F!a9$N3tG8zR*dQ6sFtW4hA2jV", "Q$@1kA!z9#L4tY7gQ#dF1bGtZ1rH8jS", #4
    "M@7h#T!m1$G4kY5pZ#bR3fCtX5qA3jM", "P$@5kA!z2#L3tY9gQ#dF2bGtZ4rH4jE", #4
    "J$@38fA!n2@K6rY4gT#dQ5fGtZ9hR1jN8", "P*2hS@q6vZ#mT@1cJ!9sY0dL%eF7iQ3r", #4
    "K!7fJ@m4dQ2tS#nY8gV%bE5xH@3zP6wR", "R@9dF#h2tY%7mZ@1sJ!4cQ6vSR3wB5xG", #4
    "KEr!7ERfJ@mweQ2tS#nY8eV%bEREweH@3zP6wR", "Rww@E9dF#h2tY%RT&REZ@1sJER!4cevSERB5xG", #4
    "L$8gT@n2dH!7sX#3mZ%bR5fJ@4qP6vY" #4
]

common_passwords = [
    'password', '123456', 'qwerty', 'letmein', 'football', 
    'welcome', 'abc123', 'admin', 'monkey', 'access', 
    'login', 'master', 'sunshine', '111111', '123123', 
    'shadow', 'passw0rd', 'baseball', 'dragon', 'football1', 
    'trustno1', 'welcome1', 'zaq1zaq1', '1234', '12345', 
    '1234567', '12345678', '123456789', 'qwerty123', 'letmein123', 
    'football123', '654321', 'superman', 'iloveyou', 'princess', 
    '000000', 'asdfgh', 'cheese', '!@#$%^'
]

security_levels = ["Too weak", "Weak", "Moderate", "Strong", "Very strong"]

passwords_to_test = [
    "StrongP@ssw0rd!", "pippo", "Bhue44#çìend jaif, meo. ow034 ggj4", "MyS3cur3P@$$w0rd",
    "C0mp13xP@ssw0rd!", "NFK 82MS ww2#]ge 344?  ?£%/?£qòKw àòàlLL"
]

labels = np.array([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4
])

for password, label in zip(passwords, labels):
    print(f"Password: '{password}' - Label: {label}")

def extract_features(password):
    features = {}
    features['length'] = len(password)
    features['has_uppercase'] = any(c.isupper() for c in password)
    features['has_digit'] = any(c.isdigit() for c in password)
    features['has_special'] = any(c in '!@#$%^&*()-_=+[{]};:\'",<.>/?' for c in password)
    features['has_sequence'] = any(str(i) in password for i in range(10))
    unique_chars = set(password)
    features['unique_char_count'] = len(unique_chars)
    features['has_common_phrase'] = any(phrase.lower() in password.lower() for phrase in common_passwords)
    return features

data = []
for password in passwords:
    features = extract_features(password)
    data.append([
        features['length'], features['has_uppercase'], features['has_digit'],
        features['has_special'], features['unique_char_count'], features['has_common_phrase']
    ])
X = np.array(data)

X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.3, random_state=42)

clf = RandomForestClassifier()
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy}")

def evaluate_password(password):
    features = extract_features(password)
    password_data = [[
        features['length'], features['has_uppercase'], features['has_digit'],
        features['has_special'], features['unique_char_count'], features['has_common_phrase']
    ]]
    prediction = clf.predict(password_data)[0]
    return security_levels[prediction]

print("\nEvaluating passwords:")
for passw in passwords_to_test:
    print(f"The password '{passw}' is: {evaluate_password(passw)}")
    
while newp := input("Insert a password to test: "):
    print(f"The password '{newp}' is: {evaluate_password(newp)}")
