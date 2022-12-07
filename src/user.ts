import { Env, User } from "./types";

export const getUser = async (username: string, env: Env) => {
    const { results } = await env.DB.prepare(
        'SELECT * FROM users WHERE username = ?'
    ).bind(username).all();

    return results?.[0] as User;
}

export const createUser = async (username: string, password: string, env: Env) => {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const saltString = new TextDecoder().decode(salt);

    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + saltString));

    const hashString = new TextDecoder().decode(hash);

    let userInfo: Omit<User, 'userId'> = {
        username,
        password: hashString,
        salt: saltString
    }

    await env.DB.prepare(
        'INSERT INTO users (username, password, salt) VALUES (?, ?, ?)'
    ).bind(userInfo.username, userInfo.password, userInfo.salt).run();

    return userInfo;
}