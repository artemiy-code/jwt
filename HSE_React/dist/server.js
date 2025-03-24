"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const bcrypt_1 = __importDefault(require("bcrypt"));
const express_1 = __importDefault(require("express"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const passport_1 = __importDefault(require("passport"));
const passport_jwt_1 = require("passport-jwt");
const passport_local_1 = require("passport-local");
const app = (0, express_1.default)();
app.use(express_1.default.json());
app.use(passport_1.default.initialize());
const SECRET_KEY = 'super_secret_key_123_!';
const storedUser = {
    id: 1,
    username: "Artem",
    hashedPassword: bcrypt_1.default.hashSync("lalalalala", 10),
};
passport_1.default.use(new passport_local_1.Strategy((username, password, done) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        if (username !== storedUser.username) {
            return done(null, false, { message: "Invalid username" });
        }
        const isValid = yield bcrypt_1.default.compare(password, storedUser.hashedPassword);
        if (!isValid) {
            return done(null, false, { message: "Invalid password" });
        }
        return done(null, storedUser);
    }
    catch (error) {
        return done(error);
    }
})));
passport_1.default.use(new passport_jwt_1.Strategy({
    jwtFromRequest: passport_jwt_1.ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: SECRET_KEY,
}, (payload, done) => {
    if (payload.id === storedUser.id) {
        return done(null, storedUser);
    }
    return done(null, false, { message: "Invalid token" });
}));
app.use((req, res, next) => {
    console.log(`[REQUEST] ${req.method} ${req.url} -`, req.body);
    next();
});
app.use((error, req, res, next) => {
    console.error("[ERROR]", error);
    res.status(500).json({ message: "Internal Server Error", error: error.message });
});
app.get("/", (req, res) => {
    res.send("Server is running)");
});
app.post("/login", (req, res, next) => {
    console.log("[LOGIN ATTEMPT]", req.body);
    passport_1.default.authenticate("local", { session: false }, (error, user, info) => {
        console.log("[AUTH RESULT]", { error, user, info });
        if (error) {
            console.error("Authentication Error:", error);
            return next(error);
        }
        if (!user) {
            console.warn("Login failed:", info === null || info === void 0 ? void 0 : info.message);
            return res.status(400).json({ path: "/login", message: (info === null || info === void 0 ? void 0 : info.message) || "Authentication Failed" });
        }
        const token = jsonwebtoken_1.default.sign({ id: user.id }, SECRET_KEY, { expiresIn: "1h" });
        return res.json({ token });
    })(req, res, next);
});
app.get("/profile", passport_1.default.authenticate("jwt", { session: false }), (req, res) => {
    res.json({
        message: "Welcome to your profile",
        user: req.user,
    });
});
const SERVER_PORT = 3001;
app.listen(SERVER_PORT, () => {
    console.log(`Server listening on http://localhost:${SERVER_PORT}`);
});
