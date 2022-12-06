export interface Env {
    DB: D1Database
}

export interface User {
    userId: string
    username: string
    password: string
    salt: string
}

export interface Session {
    sessionId: string
    userId: string
    issued: number
    expires: number
}

export type PartialSession = Omit<Session, 'issued' | 'expires'>

export interface EncodeResult {
    token: string,
    expires: number,
    issued: number
}

export interface DecodeResult {
    valid: boolean
    session?: Session;
}


export type ExpirationStatus = "expired" | "active" | "grace";
