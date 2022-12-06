import { DecodeResult, EncodeResult, PartialSession, Session } from "./types";
import { decodeJwt, jwtVerify, SignJWT } from "jose";

export const encodeSession = async (secretKey: CryptoKey | Uint8Array, partialSession: PartialSession, issuer: string, audience: string): Promise<EncodeResult> => {
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
        .setAudience(audience)
        .setExpirationTime(expires)
        .sign(secretKey);


    return {
        token: encodedToken,
        issued: issued,
        expires: expires
    };
}

export const decodeSession = async (secretKey: CryptoKey | Uint8Array, token: string, issuer: string, audience: string): Promise<DecodeResult> => {
    let result: Session;

    try {
        const decoded = await jwtVerify(token, secretKey, {
            issuer,
            audience,
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
            valid: false
        };
    }



    return {
        valid: true,
        session: result
    };
}


