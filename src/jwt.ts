import { DecodeResult, EncodeResult, PartialSession, Session } from "./types";
import { Context } from "hono";
import { Environment } from "hono/dist/types";
import { Schema } from "hono/dist/validator/schema";
import { decodeJwt, jwtVerify, SignJWT } from "jose";

// extend JWTClaimVerificationOptions to include csrf token
declare module "jose" {
    interface JWTClaimVerificationOptions {
        csrt: string;
    }
}

export const encodeSession = async (secretKey: CryptoKey | Uint8Array, partialSession: PartialSession, issuer: string, audience: string): Promise<EncodeResult> => {
    const issued = Date.now();
    const fifteenMinutesInMs = 15 * 60 * 1000;
    const expires = issued + fifteenMinutesInMs;

    const csrt = crypto.randomUUID();

    const encodedToken = await new SignJWT({
        sub: partialSession.userId,
        jti: partialSession.sessionId,
        csrt
    })
        .setProtectedHeader({ alg: "HS512" })
        .setIssuedAt(issued)
        .setIssuer(issuer)
        .setAudience(audience)
        .setExpirationTime(expires)
        .sign(secretKey);


    return {
        token: encodedToken,
        issued: issued,
        expires: expires,
        csrt: csrt
    };
}

export const decodeSession = async (secretKey: CryptoKey | Uint8Array, token: string, issuer: string, audience: string): Promise<DecodeResult> => {
    let result: Session;

    try {
        const partial = decodeJwt(token);

        const csrt = partial.csrf as string;

        const decoded = await jwtVerify(token, secretKey, {
            issuer,
            audience,
            csrt,
            algorithms: ["HS512"]
        });

        const session: Partial<Session> = {
            userId: decoded.payload.sub,
            sessionId: decoded.payload.jti,
            issued: decoded.payload.iat,
            expires: decoded.payload.exp,
            csrt: decoded.payload.csrt as string
        }

        result = session as Session;
    } catch (e) {
        return {
            valid: false,
            expired: true
        };
    }

    const isExpired = result.expires < Date.now();

    return {
        valid: true,
        expired: isExpired,
        session: result
    };
}

export const getIssuer = (c: Context<string, Environment>) => {
    const issuer = c.env.ISSUER;

    if (!issuer) {
        throw new Error('ISSUER enviroment variable not set');
    }

    return issuer;
}

export const getAudience = (c: Context<string, Environment>) => {
    return c.req.headers.get('Host');
}

export const getSessionPartial = async (c: Context<string, Environment, Schema>): Promise<PartialSession | undefined> => {
    const cookies = c.req.headers.get('Cookie')?.split(';');
    const jwt = cookies?.find(c => c.trim().startsWith('jwt='))?.split('=')[1];

    if (!jwt) {
        return undefined;
    }

    const session = decodeJwt(jwt);

    if (!session || !session.sub || !session.jti) {
        return undefined;
    }

    return {
        userId: session.sub,
        sessionId: session.jti
    }
}


export const jwtMiddleware = async (c: Context<string, Environment, Schema>, next: () => Promise<void>): Promise<void | Response> => {


    const cookies = c.req.headers.get('Cookie')?.split(';');

    const jwt = cookies?.find(c => c.trim().startsWith('jwt='))?.split('=')[1];

    const csrt = c.req.headers.get('X-CSRF-Token');

    if (!jwt || !csrt) {
        // Not authorized
        return new Response('Not authorized', { status: 401 });
    }

    // get orign of request
    const issuer = getIssuer(c);

    // get host of request
    const audience = getAudience(c);


    if (!audience) {

        return new Response('Not Authorized', { status: 400 });
    }

    // decode jwt
    const decoded = await decodeSession(
        new TextEncoder().encode(c.env.JWT_SECRET),
        jwt,
        issuer,
        audience
    )

    console.log('decoded', decoded);

    if (!decoded.valid || !decoded.session || decoded.session.csrt !== csrt) {
        return new Response('Not authorized', { status: 401 });
    }

    console.log('here')

    if (decoded.expired) {
        return new Response('Session expired', { status: 440 });
    }

    console.log('here')


    return await next()
}

