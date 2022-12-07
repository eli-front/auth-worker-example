import { DecodeResult, EncodeResult, PartialSession, Session } from "./types";
import { decodeJwt, jwtVerify, SignJWT } from "jose";
import { Context } from "hono";
import { Environment, Handler } from "hono/dist/types";
import { Schema } from "hono/dist/validator/schema";

export const encodeSession = async (secretKey: CryptoKey | Uint8Array, partialSession: PartialSession, issuer: string): Promise<EncodeResult> => {
    const issued = Date.now();
    const fifteenMinutesInMs = 15 * 60 * 1000;
    const expires = issued + fifteenMinutesInMs;
    const session: Session = {
        ...partialSession,
        issued: issued,
        expires: expires
    };

    const encodedToken = await new SignJWT({
        sub: session.userId,
        jti: session.sessionId,
    })
        .setProtectedHeader({ alg: "HS512" })
        .setIssuedAt(issued)
        .setIssuer(issuer)
        .setExpirationTime(expires)
        .sign(secretKey);


    return {
        token: encodedToken,
        issued: issued,
        expires: expires
    };
}

export const decodeSession = async (secretKey: CryptoKey | Uint8Array, token: string, issuer: string): Promise<DecodeResult> => {
    let result: Session;

    try {

        console.log(issuer)

        const decoded = await jwtVerify(token, secretKey, {
            issuer,
            algorithms: ["HS512"]
        });

        const session = {
            userId: decoded.payload.sub,
            sessionId: decoded.payload.jti,
            issued: decoded.payload.iat,
            expires: decoded.payload.exp
        }

        result = session as Session;
    } catch (e) {
        return {
            valid: false,
            status: "expired"
        };
    }

    const isExpired = result.expires < Date.now();

    const threeHoursInMs = 3 * 60 * 60 * 1000;

    const isGrace = result.expires + threeHoursInMs < Date.now();

    const status = isGrace ? "grace" : isExpired ? "expired" : "active";


    return {
        valid: true,
        status: isExpired ? "expired" : "active",
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


export const auth = async (c: Context<string, Environment, Schema>, action: ((s: Session) => Response) | ((s: Session) => Promise<Response>)): Promise<Response> => {

    const jwt = c.req.headers.get('Cookie')?.split('=')[1];

    if (!jwt) {

        console.log(1);

        // Not authorized
        return new Response('Not authorized', { status: 401 });
    }

    // get orign of request
    const issuer = getIssuer(c);

    // decode jwt
    const decoded = await decodeSession(
        new TextEncoder().encode(c.env.JWT_SECRET),
        jwt,
        issuer
    )

    if (!decoded.valid || !decoded.session) {
        console.log(decoded);
        return new Response('Not authorized', { status: 401 });
    }

    if (decoded.status === 'expired') {
        console.log(3);
        return new Response('Session expired', { status: 440 });
    }

    return await action(decoded.session);
}

