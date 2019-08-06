'use strict';

const _ = require('lodash');
const QRCode = require('qrcode');
const speakeasy = require('speakeasy');

class Secret {
    constructor(opts) {
        const { prefix, secret } = opts || {};

        this._prefix = prefix;
        if (!_.isString(secret)) {
            throw new Error('invalid secret');
        }

        this._secret = secret;
    }

    static generate(opts) {
        const { prefix, length } = opts || {};

        const secret = speakeasy.generateSecret({
            length: _.isNumber(length) ? length : 64,
            symbols: true
        });

        return new Secret({ prefix, secret: secret.ascii });
    }

    get prefix() {
        return this._prefix;
    }

    get secret() {
        return this._secret;
    }

    verify(token) {
        return speakeasy.totp.verify({
            secret: this._secret,
            token,
            window: 10
        });
    }

    expectedToken() {
        return speakeasy.totp({
            secret: this._secret
        });
    }

    generateQrCode(userId) {
        const { prefix } = this;

        const otpauth_url = speakeasy.otpauthURL({
            secret: this._secret,
            label: `${prefix ? `${prefix}:` : ''}${userId}`,
            algorithm: 'sha1'
        });

        return new Promise((resolve, reject) => {
            QRCode.toDataURL(otpauth_url, (err, image_data) => {
                if (err) {
                    return reject(err);
                }

                resolve(image_data);
            });
        });
    }

    [Symbol.toStringTag]() {
        return this._secret;
    }
}

module.exports = Secret;
