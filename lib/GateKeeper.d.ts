import express = require('express');
import Secret = require('./Secret');

declare class SecretManager {
    constructor(opts: SecretManager.CtorOpts);

    generate(): Secret;
    express(opts: SecretManager.ExpressOpts): express.Router;

    readonly appName: string;
    readonly length: number;
}

declare namespace SecretManager {
    interface CtorOpts {
        /**
         * The name of the application name that will
         * be displayed in the authenticator.
         *
         * Format: ${appName}:${userId}
         */
        appName?: string;

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

        onSerialize: (req: express.Request, tfa: Tfa) => Promise<void>;
        onDeserialize: (req: express.Request) => Promise<void>;
    }

    interface Tfa {
        verfied: boolean;
        secret: string;
    }
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
