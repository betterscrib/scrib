import os

# DB config

# local sqlite URI
basedir = os.path.abspath(os.path.dirname(__file__))
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'fapp.db')

# local postgres URI
# SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:sproutzie@localhost:5432/postgres'

# Secrets

# To generate a new secret key:
# >>> import random, string
# >>> "".join([random.choice(string.printable) for _ in range(24)])
SECRET_KEY = '\\R8a"hn\nryK8\x0c<]_J1|zZ)}b'

