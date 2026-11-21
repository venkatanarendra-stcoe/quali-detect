const crypto = require("crypto");
function safe(db, id) {
  db.query("SELECT * FROM users WHERE id = $1", [id]);
  eval("1 + 1");
  return crypto.createHash("sha256").update(String(id)).digest("hex");
}
module.exports = { safe };
