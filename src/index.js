import "dotenv/config";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// Inicializa o Supabase com a Anon Key
const supabase = createClient(
	process.env.SUPABASE_URL,
	process.env.SUPABASE_ANON_KEY
);

// Rota de login: signInWithPassword + cookie HttpOnly
app.post("/login", async (req, res) => {
	const { email, password } = req.body;
	const { data, error } = await supabase.auth.signInWithPassword({
		email,
		password,
	});
	if (error || !data?.session) {
		return res
			.status(401)
			.json({ error: error?.message || "Falha na autenticação" });
	}

	const session = data.session;

	// Emite o access_token como cookie HttpOnly
	res.cookie("access_token", session.access_token, {
		httpOnly: true,
		secure: process.env.NODE_ENV === "production",
		sameSite: "Strict",
		maxAge: session.expires_in * 1000, // em milissegundos
		path: "/",
	}).sendStatus(204);
});

// Rota de logout: expira o cookie
app.post("/logout", (_req, res) => {
	res.clearCookie("access_token", { path: "/" }).sendStatus(204);
});

// Middleware de proteção
function ensureAuthenticated(req, res, next) {
	const token = req.cookies.access_token;
	if (!token) return res.sendStatus(401);
	try {
		jwt.verify(token, process.env.SUPABASE_JWT_SECRET);
		next();
	} catch {
		res.sendStatus(401);
	}
}

// Rota "me": retorna payload do JWT
app.get("/me", ensureAuthenticated, (req, res) => {
	const token = req.cookies.access_token;
	const payload = jwt.decode(token);
	res.json(payload);
});

const port = Number(process.env.PORT) || 4444;
app.listen(port, () =>
	console.log(`Auth proxy rodando em http://localhost:${port}`)
);
