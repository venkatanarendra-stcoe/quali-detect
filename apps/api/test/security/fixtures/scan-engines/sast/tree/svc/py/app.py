import hashlib
import os
import pickle
import subprocess
import yaml
from flask import request

API_KEY = "sk_live_abcdefghijklmnop"


def handler(cur):
    name = request.args.get("name")
    cur.execute("SELECT * FROM t WHERE n = '%s'" % name)
    cur.execute(f"SELECT * FROM t WHERE n = '{name}'")
    os.system("ping " + name)
    subprocess.call("ls " + name, shell=True)
    eval(request.form.get("expr"))
    data = pickle.loads(request.get_data())
    cfg = yaml.load(request.get_data())
    h = hashlib.md5(name.encode()).hexdigest()
    with open(request.args.get("path")) as fh:
        return fh.read(), data, cfg, h
