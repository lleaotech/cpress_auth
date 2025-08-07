import "dotenv/config";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { createClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";

const app = express();

// 🔐 Configuração de CORS com origem dinâmica baseada em subdomínio
app.use(
	cors({
		origin: (origin, callback) => {
			if (!origin) return callback(null, true); // permite chamadas de ferramentas locais
			const allowedDomain = /\.cplay\.com\.br$/; // ⬅️ ajuste seu domínio principal aqui
			if (allowedDomain.test(new URL(origin).hostname)) {
				return callback(null, true);
			}
			callback(new Error("CORS: origem não permitida"));
		},
		credentials: true,
	})
);

app.use(express.json());
app.use(cookieParser());

// 🔗 Inicializa Supabase client
const supabase = createClient(
	process.env.SUPABASE_URL,
	process.env.SUPABASE_ANON_KEY
);

// 🔐 LOGIN - envia cookie HttpOnly com domínio seguro
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

	res.cookie("access_token", session.access_token, {
		httpOnly: true,
		secure: true,
		sameSite: "None", // ⬅️ necessário para subdomínios + cookies
		domain: process.env.COOKIE_DOMAIN || ".cplay.com.br", // ⬅️ essencial para cross-subdomain
		path: "/",
		maxAge: session.expires_in * 1000,
	});

	return res.sendStatus(204);
});

// 🔓 LOGOUT - remove o cookie
app.post("/logout", (_req, res) => {
	res.clearCookie("access_token", {
		path: "/",
		domain: process.env.COOKIE_DOMAIN || ".cplay.com.br",
	});
	return res.sendStatus(204);
});

// 🔐 Middleware de proteção
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

// ✅ /me retorna dados do usuário logado (decodificados)
app.get("/me", ensureAuthenticated, (req, res) => {
	const token = req.cookies.access_token;
	const payload = jwt.decode(token);
	res.json(payload);
});

// 🚀 Inicializa servidor
const port = Number(process.env.PORT) || 4444;
app.listen(port, () => {
	console.log(`✅ Auth proxy rodando em http://localhost:${port}`);
});
