'use strict';

const _ = require('lodash');
const express = require('express');
const Secret = require('./Secret');

class GateKeeper {
    constructor({ prefix, length }) {
        this._prefix = prefix;
        this._length = length || 64;
    }

    get prefix() {
        return this._prefix;
    }

    get length() {
        return this._length;
    }

    generate() {
        return Secret.generate({
            prefix: this.prefix,
            length: this.length
        });
    }

    express(opts) {
        opts = opts || {};

        const {
            routePathPrefix,
            onSecret,
            onVerified,
            userIdPath = 'email'
        } = opts;

        if (!_.isFunction(onSecret)) {
            throw new Error('onSecret needs to be a function');
        }

        if (!_.isFunction(onVerified)) {
            throw new Error('onVerified needs to be a function');
        }

        if (!_.isString(userIdPath)) {
            throw new Error('userIdPath needs to be a string');
        }

        let twoFaPath = '/2fa';
        if (_.isString(routePathPrefix)) {
            // https://regexr.com/4i4vh
            twoFaPath = routePathPrefix.replace(/^\/?(.+)$/, '/$1');
        }

        const twoFaVerifyUrl = `${twoFaPath}/verify`;
        const { successRedirect = '/', failureRedirect = twoFaPath } = opts;

        const router = express.Router();

        router.use(async (req, _res, next) => {
            const { user, session } = req;

            if (!session) {
                return next(new Error('no session found'));
            }

            if (user.secret) {
                req.secret = new Secret({
                    prefix: this.prefix,
                    secret: user.secret
                });
            }

            req.isTwoFactorVerified = () => session.twoFactorVerified;

            next();
        });

        router.get(twoFaPath, async (req, res) => {
            let { secret, user } = req;

            if (req.isTwoFactorVerified()) {
                return res.redirect(successRedirect);
            }

            if (!secret) {
                secret = this.generate();
                await new Promise((resolve, reject) => {
                    onSecret(req, secret.secret, err => {
                        if (err) {
                            return reject(err);
                        }

                        resolve();
                    });
                });
            }

            let qrImage;
            if (!user.twoFaVerified) {
                qrImage = await secret.generateQrCode(_.get(user, userIdPath));
            }

            const resObj = {
                qrImage,
                verifyUrl: twoFaVerifyUrl
            };

            const isAjaxRequest = req.xhr;
            if (isAjaxRequest) {
                return res.json(resObj);
            }

            res.render('two-fa', resObj);
        });

        router.post(twoFaVerifyUrl, async (req, res) => {
            const {
                secret,
                session,
                body: { token }
            } = req;

            const resObj = {
                redirect: successRedirect || '/'
            };

            if (!req.isTwoFactorVerified()) {
                if (secret && secret.verify(token)) {
                    session.twoFactorVerified = true;
                    await new Promise((resolve, reject) => {
                        onVerified(req, err => {
                            if (err) {
                                return reject(err);
                            }

                            resolve();
                        });
                    });
                } else {
                    resObj.redirect = failureRedirect;
                }
            }

            const isAjaxRequest = req.xhr;
            if (isAjaxRequest) {
                return res.json(resObj);
            }

            res.redirect(resObj.redirect);
        });

        router.use((req, res, next) => {
            const { session } = req;

            if (!session) {
                return res.send('temporarily unavailable');
            }

            if (session.twoFactorVerified) {
                return next();
            }

            res.redirect(twoFaPath);
        });

        return router;
    }
}

module.exports = GateKeeper;
