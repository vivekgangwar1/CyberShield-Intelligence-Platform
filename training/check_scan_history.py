from backend.database import get_connection

connection = get_connection()

rows = connection.execute("""
    SELECT *
    FROM scan_history
    ORDER BY id DESC
""").fetchall()

print(f"Total scans saved: {len(rows)}")

for row in rows:
    print(dict(row))

connection.close()