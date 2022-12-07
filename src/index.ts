import { Hono } from 'hono'
import { serialize } from './cookie';
import { auth, encodeSession, getAudience, getIssuer } from './jwt';
import { Env, User } from './types';
import { createUser, getUser } from './user';

const app = new Hono()

app.post(
	'/api/login',
	async c => {
		const { password, username } = await c.req.json() as { password: string, username: string }

		let user: User

		try {
			user = await getUser(username, c.env as Env);
			if (!user) {
				throw new Error('User not found');
			}
		} catch (e) {
			return new Response('Not Authorized', { status: 400 });
		}

		// hash password with salt 
		const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + user.salt));

		// // compare hash with password
		if (new TextDecoder().decode(hash) !== user.password) {
			return new Response('Not Authorized', { status: 400 });
		}


		const audience = getAudience(c);
		if (!audience) {
			return new Response('Not Authorized', { status: 400 });
		}

		const jwt = await encodeSession(
			new TextEncoder().encode(c.env.JWT_SECRET),
			{
				sessionId: crypto.randomUUID(),
				userId: user.userId
			},
			getIssuer(c),
			audience
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

		try {
			createUser(username, password, c.env as Env);
		} catch (e) {
			return new Response('Failed to create new user', { status: 400 });
		}

		const user = await getUser(username, c.env as Env);
		if (!user) {
			return new Response('Not Authorized', { status: 400 });
		}

		const audience = getAudience(c);
		if (!audience) {
			return new Response('Not Authorized', { status: 400 });
		}

		const jwt = await encodeSession(
			new TextEncoder().encode(c.env.JWT_SECRET),
			{
				sessionId: crypto.randomUUID(),
				userId: user.userId
			},
			getIssuer(c),
			audience
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

	const audience = getAudience(c);
	if (!audience) {
		return new Response('Not Authorized', { status: 400 });
	}

	const result = await encodeSession(new TextEncoder().encode(c.env.JWT_SECRET), s, getIssuer(c), audience)

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