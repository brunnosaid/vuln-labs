# init_db.py
import sqlite3
import os

DB = 'data/db.sqlite3'
os.makedirs('data', exist_ok=True)

conn = sqlite3.connect(DB)
c = conn.cursor()

# XSS stored messages
c.execute('CREATE TABLE IF NOT EXISTS xss_messages (id INTEGER PRIMARY KEY, name TEXT, message TEXT);')

# Users for SQLi lab
c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, fullname TEXT);')
try:
    c.execute("INSERT INTO users (username,password,fullname) VALUES ('admin','adminpass','Administrator');")
    c.execute("INSERT INTO users (username,password,fullname) VALUES ('alice','alice123','Alice Silva');")
    c.execute("INSERT INTO users (username,password,fullname) VALUES ('bob','bob123','Bob Souza');")
except:
    pass

conn.commit()
conn.close()
print("DB inicializado em", DB)
