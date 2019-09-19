'use strict';

const _ = require('lodash');
const express = require('express');
const Secret = require('./Secret');

class GateKeeper {
    constructor({ appName, length }) {
        this._appName = appName;
        this._length = length || 64;
    }

    get appName() {
        return this._appName;
    }

    get length() {
        return this._length;
    }

    generate() {
        return Secret.generate({
            appName: this.appName,
            length: this.length
        });
    }

    verify(tfa, token) {
        const secret = new Secret({
            appName: this.appName,
            secret: tfa.secret
        });

        return secret.verify(token);
    }

    express(opts) {
        opts = opts || {};

        let {
            routePathPrefix = '/tfa',
            onSerialize,
            onDeserialize,
            userIdPath = 'email'
        } = opts;

        if (!_.isString(routePathPrefix)) {
            throw new Error('routePathPrefix needs to be a string');
        }

        if (onSerialize && !_.isFunction(onSerialize)) {
            throw new Error('onSerialize needs to be a function');
        }

        if (onDeserialize && !_.isFunction(onDeserialize)) {
            throw new Error('onDeserialize needs to be a function');
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
                onSerialize,
                onDeserialize,
                userIdPath,
                twoFaVerifyUrl
            })
        );

        router.post(
            twoFaVerifyUrl,
            this.postMiddleware({
                successRedirect,
                onSerialize,
                onDeserialize,
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

    getMiddleware({
        successRedirect,
        onSerialize,
        onDeserialize,
        userIdPath,
        twoFaVerifyUrl
    }) {
        return async (req, res) => {
            if (req.isTwoFactorVerified()) {
                return res.redirect(successRedirect);
            }

            const { user } = req;

            if (!user) {
                return res.redirect(successRedirect);
            }

            const tfa = (await onDeserialize(req)) || {
                verified: false
            };

            let secret;
            if (!tfa.secret) {
                secret = this.generate();
                tfa.secret = secret.secret;

                onSerialize && (await onSerialize(req, tfa));
            } else {
                secret = new Secret({
                    appName: this.appName,
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

    postMiddleware({
        successRedirect,
        onDeserialize,
        onSerialize,
        failureRedirect
    }) {
        return async (req, res) => {
            const {
                session,
                body: { token }
            } = req;

            const tfa = await onDeserialize(req);

            const resObj = {
                redirect: successRedirect || '/'
            };

            if (!req.isTwoFactorVerified()) {
                if (this.verify(tfa, token)) {
                    session.twoFactorVerified = true;

                    if (!tfa.verified) {
                        tfa.verified = true;

                        onSerialize && (await onSerialize(req, tfa));
                    }
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
