declare class Secret {
    constructor(opts: Secret.CtorOpts);

    verify(token: string): boolean;
    generateQrCode(userId: string): Promise<string>;

    static generate(opts?: Secret.GenerateOpts): Secret;

    readonly appName: string;
    readonly secret: string;
}

declare namespace Secret {
    interface CtorOpts {
        /**
         * The name of the application name that will
         * be displayed in the authenticator.
         *
         * Format: ${appName}:${userId}
         */
        appName?: string;

        secret: string;
    }

    interface GenerateOpts {
        appName?: string;
        length?: number;
    }
}

export = Secret;
