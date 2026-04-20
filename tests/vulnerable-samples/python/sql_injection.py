# SR1-1: SQL Injection vulnerable code
import sqlite3

def get_user(user_input):
    conn = sqlite3.connect("test.db")
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor = conn.execute(query)
    return cursor.fetchall()

def search_products(category):
    conn = sqlite3.connect("shop.db")
    conn.execute("SELECT * FROM products WHERE category = '" + category + "'")
