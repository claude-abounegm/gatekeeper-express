declare class Secret {
    constructor(opts: Secret.CtorOpts);

    verify(token: string): boolean;
    generateQrCode(userId: string): Promise<string>;

    static generate(opts?: Secret.GenerateOpts): Secret;

    readonly prefix: string;
    readonly secret: string;
}

declare namespace Secret {
    interface CtorOpts {
        /**
         * The name of the application name that will
         * be displayed in the authenticator.
         * 
         * Format: ${prefix}:${userId}
         */
        prefix?: string;

        secret: string;
    }

    interface GenerateOpts {
        prefix?: string;
        length?: number;
    }
}

export = Secret;
