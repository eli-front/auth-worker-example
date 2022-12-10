import { Hono } from 'hono'
import { serialize } from './cookie';
import { encodeSession, getAudience, getIssuer, getSessionPartial, jwtMiddleware } from './jwt';
import { Env, User } from './types';
import { createUser, getUser } from './user';

const app = new Hono()

app.use('/api/session', jwtMiddleware)
app.use('/api/csrt', jwtMiddleware)
app.use('/api/protected/*', jwtMiddleware)


app.all('/api/protected/info', c => {
	return new Response('This is protected information')
})

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

		const sessionId = crypto.randomUUID();

		const jwt = await encodeSession(
			new TextEncoder().encode(c.env.JWT_SECRET),
			{
				sessionId: sessionId,
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

		const csrfCookie = serialize('csrf', jwt.csrt, {
			sameSite: 'strict',
			secure: c.env.DEVELOPMENT != true,
			expires: new Date(jwt.expires)
		})

		const headers = new Headers();
		headers.set('Content-Type', 'application/json');
		headers.append('Set-Cookie', cookie);
		headers.append('Set-Cookie', csrfCookie);

		return new Response(JSON.stringify({
			userId: user.userId,
		}), {
			status: 200, headers: headers
		});
	}
)

app.post('/api/logout', async c => {
	const cookie = serialize('jwt', '', {
		httpOnly: true,
		sameSite: 'strict',
		secure: c.env.DEVELOPMENT != true,
		expires: new Date(0)
	})

	return new Response('Logged out', {
		status: 200, headers: {
			'Set-Cookie': cookie
		}
	});
})

app.post(
	'/api/signup',
	async c => {
		const { password, username } = await c.req.json() as { password: string, username: string }
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

		const csrfCookie = serialize('csrf', jwt.csrt, {
			sameSite: 'strict',
			secure: c.env.DEVELOPMENT != true,
			expires: new Date(jwt.expires)
		})

		const headers = new Headers();
		headers.set('Content-Type', 'application/json');
		headers.append('Set-Cookie', cookie);
		headers.append('Set-Cookie', csrfCookie);

		return new Response(JSON.stringify({ success: true }), {
			status: 200, headers: headers
		});
	}
)

app.get('/api/session', async c => {

	console.log('session');

	const session = await getSessionPartial(c);

	console.log(session);
	if (!session) {
		return new Response('Not Authorized', { status: 400 });
	}

	const audience = getAudience(c);
	if (!audience) {
		return new Response('Not Authorized', { status: 400 });
	}
	const jwt = await encodeSession(
		new TextEncoder().encode(c.env.JWT_SECRET),
		{
			sessionId: session.sessionId,
			userId: session.userId
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

	const csrfCookie = serialize('csrf', jwt.csrt, {
		sameSite: 'strict',
		secure: c.env.DEVELOPMENT != true,
		expires: new Date(jwt.expires)
	})

	const headers = new Headers();
	headers.set('Content-Type', 'application/json');
	headers.append('Set-Cookie', cookie);
	headers.append('Set-Cookie', csrfCookie);

	return new Response(JSON.stringify({
		session: session,
	}), {
		status: 200, headers: headers
	});
})



export default app;