import hashlib
import subprocess


def safe(cur, name):
    cur.execute("SELECT * FROM t WHERE n = %s", (name,))
    subprocess.run(["ls", name], check=False)
    return hashlib.sha256(name.encode()).hexdigest()
