/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `wrangler dev src/index.ts` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `wrangler publish src/index.ts --name my-worker` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */



import { Hono } from 'hono'

const app = new Hono()

export interface Env {
	DB: D1Database
}

type user = {
	userId: string,
	username: string,
	password: string,
	salt: string,
}


const getUser = async (username: string, env: Env) => {
	const { results } = await env.DB.prepare(
		'SELECT * FROM users WHERE username = ?'
	).bind(username).all();

	return results?.[0] as user;
}

app.post(
	'/api/user/login',
	async c => {
		const { password, username } = await c.req.json() as { password: string, username: string }

		const user = await getUser(username, c.env as Env);
		if (!user) {
			return new Response('User not found', { status: 400 });
		}

		console.log(user.salt)


		// hash password with salt 
		const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + user.salt));


		console.log(new TextDecoder().decode(hash));

		// // compare hash with password
		if (new TextDecoder().decode(hash) !== user.password) {
			return new Response('Incorrect password', { status: 400 });
		}


		return new Response(JSON.stringify(user), { status: 200, headers: { 'Content-Type': 'application/json' } });
	}
)

app.post(
	'/api/user/signup',

	async c => {
		const { password, username } = await c.req.json() as { password: string, username: string }

		// Generate a long random salt using a CSPRNG.

		const salt = crypto.getRandomValues(new Uint8Array(32));
		const saltString = new TextDecoder().decode(salt);

		console.log(saltString);

		const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + saltString));

		const hashString = new TextDecoder().decode(hash);

		console.log(hashString);


		const user: Omit<user, 'userId'> = {
			username,
			password: hashString,
			salt: saltString
		}

		try {
			await c.env.DB.prepare(
				'INSERT INTO users (username, password, salt) VALUES (?, ?, ?)'
			).bind(user.username, user.password, user.salt).run();

		} catch (e) {
			return new Response('Failed to create new user', { status: 400 });
		}


		return new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json' } });




	}
)


export default app;