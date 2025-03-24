import bcrypt from "bcrypt";
import express, { Request, Response } from "express";
import jwt from "jsonwebtoken";
import passport from "passport";
import { ExtractJwt, Strategy as JWTStrategy } from "passport-jwt";
import { Strategy as LocalStrategy } from "passport-local";

const app = express();
app.use(express.json());
app.use(passport.initialize());

const SECRET_KEY = 'super_secret_key_123_!';

interface User {
  id: number;
  username: string;
  hashedPassword: string;
}

const storedUser: User = {
  id: 1,
  username: "Artem",
  hashedPassword: bcrypt.hashSync("lalalalala", 10),
};

passport.use(
  new LocalStrategy(async (username: string, password: string, done) => {
    try {
      if (username !== storedUser.username) {
        return done(null, false, { message: "Invalid username" });
      }
      
      const isValid = await bcrypt.compare(password, storedUser.hashedPassword);
      if (!isValid) {
        return done(null, false, { message: "Invalid password" });
      }
      
      return done(null, storedUser);
    } catch (error) {
      return done(error);
    }
  })
);

type TokenPayload = { id: number };
passport.use(
  new JWTStrategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: SECRET_KEY,
    },
    (payload: TokenPayload, done) => {
      if (payload.id === storedUser.id) {
        return done(null, storedUser);
      }
      return done(null, false, { message: "Invalid token" });
    }
  )
);

app.use((req, res, next) => {
  console.log(`[REQUEST] ${req.method} ${req.url} -`, req.body);
  next();
});

app.use((error: any, req: Request, res: Response, next: any) => {
  console.error("[ERROR]", error);
  res.status(500).json({ message: "Internal Server Error", error: error.message });
});

app.get("/", (req: Request, res: Response) => {
  res.send("Server is running)");
});

app.post("/login", (req: Request, res: Response, next) => {
  console.log("[LOGIN ATTEMPT]", req.body);

  passport.authenticate("local", { session: false }, (error: any, user: User | false, info: { message?: string }) => {
    console.log("[AUTH RESULT]", { error, user, info });

    if (error) {
      console.error("Authentication Error:", error);
      return next(error);
    }
    
    if (!user) {
      console.warn("Login failed:", info?.message);
      return res.status(400).json({ path: "/login", message: info?.message || "Authentication Failed" });
    }

    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: "1h" });
    return res.json({ token });
  })(req, res, next);
});

app.get(
  "/profile",
  passport.authenticate("jwt", { session: false }),
  (req: Request, res: Response) => {
    res.json({
      message: "Welcome to your profile",
      user: req.user,
    });
  }
);

const SERVER_PORT = 3001;
app.listen(SERVER_PORT, () => {
  console.log(`Server listening on http://localhost:${SERVER_PORT}`);
});