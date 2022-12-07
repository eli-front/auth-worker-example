import { Hono } from 'hono'
import { serialize } from './cookie';
import { auth, decodeSession, encodeSession, getIssuer } from './jwt';
import { Env, User } from './types';

const app = new Hono()


const getUser = async (username: string, env: Env) => {
	const { results } = await env.DB.prepare(
		'SELECT * FROM users WHERE username = ?'
	).bind(username).all();

	return results?.[0] as User;
}

app.post(
	'/api/login',
	async c => {
		const { password, username } = await c.req.json() as { password: string, username: string }

		const user = await getUser(username, c.env as Env);
		if (!user) {
			return new Response('Not Authorized', { status: 400 });
		}

		// hash password with salt 
		const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + user.salt));

		// // compare hash with password
		if (new TextDecoder().decode(hash) !== user.password) {
			return new Response('Not Authorized', { status: 400 });
		}

		const jwt = await encodeSession(
			new TextEncoder().encode(c.env.JWT_SECRET),
			{
				sessionId: crypto.randomUUID(),
				userId: user.userId
			},
			getIssuer(c),
		)

		const cookie = serialize('jwt', jwt.token, {
			httpOnly: true,
			sameSite: 'strict',
			secure: c.env.DEVELOPMENT != true,
			expires: new Date(jwt.expires)
		})

		return new Response(JSON.stringify(user), {
			status: 200, headers: {
				'Content-Type': 'application/json',
				'Set-Cookie': cookie
			}
		});
	}
)

app.post(
	'/api/signup',

	async c => {
		const { password, username } = await c.req.json() as { password: string, username: string }

		// Generate a long random salt using a CSPRNG.

		const salt = crypto.getRandomValues(new Uint8Array(32));
		const saltString = new TextDecoder().decode(salt);

		const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + saltString));

		const hashString = new TextDecoder().decode(hash);

		let userInfo: Omit<User, 'userId'> = {
			username,
			password: hashString,
			salt: saltString
		}

		try {
			await c.env.DB.prepare(
				'INSERT INTO users (username, password, salt) VALUES (?, ?, ?)'
			).bind(userInfo.username, userInfo.password, userInfo.salt).run();

		} catch (e) {
			return new Response('Failed to create new user', { status: 400 });
		}

		const user = await getUser(username, c.env as Env);

		if (!user) {
			return new Response('Not Authorized', { status: 400 });
		}

		const jwt = await encodeSession(
			new TextEncoder().encode(c.env.JWT_SECRET),
			{
				sessionId: crypto.randomUUID(),
				userId: user.userId
			},
			getIssuer(c),
		)

		const cookie = serialize('jwt', jwt.token, {
			httpOnly: true,
			sameSite: 'strict',
			secure: c.env.DEVELOPMENT != true,
			expires: new Date(jwt.expires)
		})

		return new Response(JSON.stringify({ success: true }), {
			status: 200, headers: {
				'Content-Type': 'application/json',
				'Set-Cookie': cookie
			}
		});
	}
)

app.get('/api/session', async c => await auth(c, async (s) => {

	const result = await encodeSession(new TextEncoder().encode(c.env.JWT_SECRET), s, getIssuer(c))

	const cookie = serialize('jwt', result.token, {
		httpOnly: true,
		sameSite: 'strict',
		secure: c.env.DEVELOPMENT != true,
		expires: new Date(result.expires)
	})

	return new Response(JSON.stringify({
		session: s,
	}), {
		status: 200, headers: {
			'Content-Type': 'application/json',
			'Set-Cookie': cookie
		}
	});
}))



export default app;