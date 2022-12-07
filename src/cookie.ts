const fieldContentRegExp = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;

interface SerializeOptions {
    encode?: (val: string) => string;
    maxAge?: number;
    domain?: string;
    path?: string;
    expires?: Date;
    httpOnly?: boolean;
    secure?: boolean;
    priority?: 'low' | 'medium' | 'high';
    sameSite?: true | 'lax' | 'strict' | 'none';
}

export const serialize = (name: string, val: string, options: SerializeOptions = {}) => {

    if (!fieldContentRegExp.test(name)) {
        throw new TypeError('argument name is invalid');
    }

    const value = options?.encode ? options.encode(val) : val;

    if (value && !fieldContentRegExp.test(value)) {
        throw new TypeError('argument val is invalid');
    }

    let str = name + '=' + value;

    if (options.maxAge != null) {
        const maxAge = options.maxAge;

        if (isNaN(maxAge) || !isFinite(maxAge)) {
            throw new TypeError('option maxAge is invalid')
        }

        str += '; Max-Age=' + Math.floor(maxAge);
    }

    if (options.domain != null) {
        if (!fieldContentRegExp.test(options.domain)) {
            throw new TypeError('option domain is invalid');
        }

        str += '; Domain=' + options.domain;
    }

    if (options.path != null) {
        if (!fieldContentRegExp.test(options.path)) {
            throw new TypeError('option path is invalid');
        }

        str += '; Path=' + options.path;
    }

    if (options.expires) {
        try {
            str += '; Expires=' + options.expires.toUTCString()
        } catch (e) {
            throw new TypeError('option expires is invalid Date');
        }
    }

    if (options.httpOnly) {
        str += '; HttpOnly';
    }

    if (options.secure) {
        str += '; Secure';
    }

    if (options.priority) {
        switch (options.priority) {
            case 'low':
                str += '; Priority=Low'
                break
            case 'medium':
                str += '; Priority=Medium'
                break
            case 'high':
                str += '; Priority=High'
                break
        }
    }

    if (options.sameSite != null) {

        switch (options.sameSite) {
            case true:
                str += '; SameSite=Strict';
                break;
            case 'lax':
                str += '; SameSite=Lax';
                break;
            case 'strict':
                str += '; SameSite=Strict';
                break;
            case 'none':
                str += '; SameSite=None';
                break;
        }
    }

    return str;
}

