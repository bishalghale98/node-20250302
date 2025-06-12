import { verifyJWT } from "../utils/jwt.js";

async function auth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    let token;

    if (authHeader?.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    } else if (req.headers.cookie) {
      const cookies = Object.fromEntries(
        req.headers.cookie.split("; ").map(cookie => cookie.split("="))
      );
      token = cookies.token;
    }

    if (!token) {
      return res.status(401).json({ error: "Unauthorized: No token provided" });
    }

    const userData = await verifyJWT(token);
    req.user = userData;

    next();
  } catch (err) {
    res.status(403).json({ error: "Forbidden: Invalid or expired token" });
  }
}

export default auth;
