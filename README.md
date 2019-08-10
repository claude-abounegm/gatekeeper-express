# gatekeeper-express

The one and only Two Factor Authentication Handler for Express.

Tested with `Authy` and `Google Authenticator`

![You shall not pass](https://www.meme-arsenal.com/memes/4327bd2e8c9ad98e5703afa1ba3333c0.jpg)

# Install
`npm i gatekeeper-express`

## Peer dependencies
`npm i lodash express`
***

# Requirements
* express-session
* passport (ie. `req.user`)
* some rendering engine (vash, ejs, etc)

# Usage

## Middleware
```js
'use strict';

const { GateKeeper } = require('gatekeeper-express');

const gateKeeper = new GateKeeper({
    prefix: 'App',
    length: 64
});

app.use(
    gateKeeper.express({
        routePathPrefix: '/2fa',
        userIdPath: 'email',
        onSecret: (req, secret, next) => {
            // update database here
            req.user.secret = secret;
            next();
        },
        onVerified: (req, next) => {
            // update db here
            req.user.twoFaVerified = true;
            next();
        }
    })
);
```
***
## View
GateKeeper uses `res.render('two-fa')` to render the page with qr image.

This is an example in Vash. Please adapt it to your app.
```html
<div class="text-center">
    <h4 class="h4 text-gray-900 mb-3">Two Factor Authentication</h4>
</div>

<form autocomplete="off" action="@model.verifyUrl" method="POST" class="user">
    <input autocomplete="off" name="hidden" type="text" style="display:none;">
    @if (model.qrImage) {
        <div class="text-center mb-2">
            <img src="@model.qrImage">
        </div>
    }

    <div class="form-group">
        <input 
            type="text"
            class="form-control form-control-user"
            id="token-input"
            name="token"
            placeholder="Enter verification token...">
    </div>

    <button class="btn btn-primary btn-user btn-block" type="submit">Verify</button>
</form>

<script>$('#token-input').focus();</script>
```
***
## AJAX
You can also use Ajax.

If you request `/2fa` with Ajax it will send back in JSON: `{ qrImage: string; verifyUrl: string; }`

Do a `POST` request to `verifyUrl` and GateKeeper will send back a `JSON` object with a redirect url to use: `{  redirect: string; }` if needed.

***
# Reset
To reset a user's 2-fa, simply delete `user.secret`.
***

Made with ❤ at [Income Store](http://incomestore.com) in _Lancaster, PA_.