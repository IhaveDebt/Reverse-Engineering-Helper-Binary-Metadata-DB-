"""
Reverse Engineering Helper (Binary Metadata DB)
Single-file program demonstrating defensive binary metadata collection and SQL search.
"""

import psycopg
import pandas as pd

DB_URL = "postgresql://postgres:postgres@localhost:5432/reverse_db"

SAMPLE_BINARIES = [
    {"name":"sample1.exe","imports":["kernel32.dll","user32.dll"],"strings":["Hello","World"],"func_hashes":["a1b2","c3d4"]},
    {"name":"sample2.exe","imports":["kernel32.dll"],"strings":["Test"],"func_hashes":["a1b2","e5f6"]}
]

def init_db():
    with psycopg.connect(DB_URL, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS binaries (
                name TEXT PRIMARY KEY,
                imports TEXT[],
                strings TEXT[],
                func_hashes TEXT[]
            );
            """)

def ingest_binaries(samples):
    with psycopg.connect(DB_URL, autocommit=True) as conn:
        with conn.cursor() as cur:
            for bin in samples:
                cur.execute("""
                INSERT INTO binaries (name, imports, strings, func_hashes)
                VALUES (%s,%s,%s,%s)
                ON CONFLICT (name) DO UPDATE SET imports=%s, strings=%s, func_hashes=%s
                """, (bin["name"], bin["imports"], bin["strings"], bin["func_hashes"],
                      bin["imports"], bin["strings"], bin["func_hashes"]))
    print(f"Ingested {len(samples)} binaries.")

def search_func_hash(hash_query):
    with psycopg.connect(DB_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("""
            SELECT name, func_hashes FROM binaries
            WHERE %s = ANY(func_hashes)
            """, (hash_query,))
            rows = cur.fetchall()
            for r in rows:
                print(f"Binary: {r[0]}, Matching Hashes: {r[1]}")

if __name__ == "__main__":
    init_db()
    ingest_binaries(SAMPLE_BINARIES)
    print("Reverse Engineering Helper\n")
    while True:
        query = input("Enter function hash to search (or 'exit'): ")
        if query.lower() == "exit":
            break
        search_func_hash(query)
