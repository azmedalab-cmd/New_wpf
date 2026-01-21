// id: backend-auth-controller
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import db from "../config/db.js";

export async function signup(req, res) {
  const { name, email, password } = req.body;

  const hashed = await bcrypt.hash(password, 10);

  const user = await db.query(
    "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email",
    [name, email, hashed]
  );

  const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET);

  res.json({ success: true, token, user: user.rows[0] });
}

export async function login(req, res) {
  const { email, password } = req.body;

  const user = await db.query("SELECT * FROM users WHERE email=$1", [email]);

  if (!user.rows.length) {
    return res.json({ success: false, message: "User not found" });
  }

  const valid = await bcrypt.compare(password, user.rows[0].password);
  if (!valid) {
    return res.json({ success: false, message: "Invalid password" });
  }

  const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET);

  res.json({
    success: true,
    token,
    user: { id: user.rows[0].id, name: user.rows[0].name, email: user.rows[0].email }
  });
}

export async function me(req, res) {
  const user = await db.query("SELECT id, name, email FROM users WHERE id=$1", [
    req.user.id,
  ]);

  res.json({ success: true, user: user.rows[0] });
}
