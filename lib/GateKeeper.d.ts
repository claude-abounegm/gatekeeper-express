import express = require('express');
import Secret = require('./Secret');

declare class SecretManager {
    constructor(opts: SecretManager.CtorOpts);

    generate(): Secret;
    express(opts: SecretManager.ExpressOpts): express.Router;

    readonly prefix: string;
    readonly length: number;
}

declare namespace SecretManager {
    interface CtorOpts {
        /**
         * The name of the application name that will
         * be displayed in the authenticator.
         *
         * Format: ${prefix}:${userId}
         */
        prefix?: string;

        /**
         * @default 64
         */
        length?: number;
    }

    interface ExpressOpts {
        /**
         * @default "/tfa"
         */
        routePathPrefix?: string;

        /**
         * The path to access the identification of
         * the user in `req.user`. Default is `"email"`,
         * so the name of the user will be pulled from
         * `req.user.email`. You can enter any valid
         * path. `req.user` will be used as the object
         * to retrieve the id from.
         *
         * @see https://lodash.com/docs/#get for more details on path
         *
         * @default "email"
         */
        userIdPath?: string;

        onSecret?: (req: express.Request, next: NextFn) => void;
        onVerified?: (req: express.Request, next: NextFn) => void;
    }

    type NextFn = (err?: Error) => void;
}

declare global {
    namespace Express {
        interface Response {
            secret?: Secret;
            isTwoFactorVerified: () => boolean;
        }
    }
}

export = SecretManager;
