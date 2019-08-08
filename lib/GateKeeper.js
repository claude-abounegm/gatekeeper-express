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

        let {
            routePathPrefix = '/2fa',
            onSecret,
            onVerified,
            userIdPath = 'email'
        } = opts;

        if (!_.isString(routePathPrefix)) {
            throw new Error('routePathPrefix needs to be a string');
        }

        if (!_.isFunction(onSecret)) {
            throw new Error('onSecret needs to be a function');
        }

        if (!_.isFunction(onVerified)) {
            throw new Error('onVerified needs to be a function');
        }

        if (!_.isString(userIdPath)) {
            throw new Error('userIdPath needs to be a string');
        }

        // https://regexr.com/4ipld
        routePathPrefix = routePathPrefix.replace(/^\/?(.*?)\/?$/, '/$1');

        const twoFaVerifyUrl = `${routePathPrefix}/verify`;
        const {
            successRedirect = '/',
            failureRedirect = routePathPrefix
        } = opts;

        const router = express.Router();

        router.use(this.beforeMiddleware());

        router.get(
            routePathPrefix,
            this.getMiddleware({
                successRedirect,
                onSecret,
                userIdPath,
                twoFaVerifyUrl
            })
        );

        router.post(
            twoFaVerifyUrl,
            this.postMiddleware({
                successRedirect,
                onVerified,
                failureRedirect
            })
        );

        router.use(this.afterMiddleware({ routePathPrefix }));

        return router;
    }

    beforeMiddleware() {
        return async (req, _res, next) => {
            const { user, session } = req;

            if (!session) {
                return next(new Error('no session found'));
            }

            if (user && user.secret) {
                req.secret = new Secret({
                    prefix: this.prefix,
                    secret: user.secret
                });
            }

            req.isTwoFactorVerified = () => user && session.twoFactorVerified;

            next();
        };
    }

    getMiddleware({ successRedirect, onSecret, userIdPath, twoFaVerifyUrl }) {
        return async (req, res) => {
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
        };
    }

    postMiddleware({ successRedirect, onVerified, failureRedirect }) {
        return async (req, res) => {
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
        };
    }

    afterMiddleware({ routePathPrefix }) {
        return (req, res, next) => {
            const { session } = req;

            if (!session) {
                return res.send('temporarily unavailable');
            }

            if (!req.user || session.twoFactorVerified) {
                return next();
            }

            res.redirect(routePathPrefix);
        };
    }
}

module.exports = GateKeeper;
