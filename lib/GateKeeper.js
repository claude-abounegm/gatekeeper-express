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

        let { routePathPrefix = '/tfa', onUpdate, userIdPath = 'email' } = opts;

        if (!_.isString(routePathPrefix)) {
            throw new Error('routePathPrefix needs to be a string');
        }

        if (onUpdate && !_.isFunction(onUpdate)) {
            throw new Error('onUpdate needs to be a function');
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
                onUpdate,
                userIdPath,
                twoFaVerifyUrl
            })
        );

        router.post(
            twoFaVerifyUrl,
            this.postMiddleware({
                successRedirect,
                onUpdate,
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

            req.isTwoFactorVerified = () => user && session.twoFactorVerified;

            next();
        };
    }

    getMiddleware({ successRedirect, onUpdate, userIdPath, twoFaVerifyUrl }) {
        return async (req, res) => {
            if (req.isTwoFactorVerified()) {
                return res.redirect(successRedirect);
            }

            const { user } = req;

            if (!user) {
                return res.redirect(successRedirect);
            }

            const tfa = user.tfa || {
                verified: false
            };

            let secret;
            if (!tfa.secret) {
                secret = this.generate();
                tfa.secret = secret.secret;

                onUpdate &&
                    (await new Promise((resolve, reject) => {
                        onUpdate(req, tfa, err => {
                            if (err) {
                                return reject(err);
                            }

                            resolve();
                        });
                    }));
            } else {
                secret = new Secret({
                    prefix: this.prefix,
                    secret: tfa.secret
                });
            }

            let qrImage;
            if (!tfa.verified) {
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

    postMiddleware({ successRedirect, onUpdate, failureRedirect }) {
        return async (req, res) => {
            const {
                user,
                secret,
                session,
                body: { token }
            } = req;

            const { tfa } = user;

            const resObj = {
                redirect: successRedirect || '/'
            };

            if (!req.isTwoFactorVerified()) {
                if (secret && secret.verify(token)) {
                    tfa.verified = true;
                    session.twoFactorVerified = true;

                    onUpdate &&
                        (await new Promise((resolve, reject) => {
                            onUpdate(req, tfa, err => {
                                if (err) {
                                    return reject(err);
                                }

                                resolve();
                            });
                        }));
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
