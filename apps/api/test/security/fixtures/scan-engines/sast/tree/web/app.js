const express = require("express");
const cp = require("child_process");
const fs = require("fs");
const crypto = require("crypto");
const serialize = require("node-serialize");
const app = express();

const dbPassword = "hunter2-hunter2-hunter2";

app.get("/user", (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id);
  db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
  cp.exec("ls " + req.query.dir);
  eval(req.body.code);
  const obj = serialize.unserialize(req.body.payload);
  fs.readFile(req.query.file, "utf8", () => {});
  const h = crypto.createHash("md5").update(req.body.pw).digest("hex");
  res.send(h);
});
