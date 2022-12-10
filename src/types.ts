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
    csrt: string
}

export type PartialSession = Omit<Session, 'issued' | 'expires' | 'csrt'>

export interface EncodeResult {
    token: string,
    expires: number,
    issued: number
    csrt: string
}

export interface DecodeResult {
    valid: boolean
    expired: boolean
    session?: Session;
}

