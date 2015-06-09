/**
 * Module dependencies.
 */
var util = require('util'),
    url = require('url'),
    OAuth2Strategy = require('passport-oauth2').Strategy,
    AuthorizationError = require('passport-oauth2').AuthorizationError,
    InternalOAuthError = require('passport-oauth2').InternalOAuthError;

function QuizletStrategy(options, verify) {
    options = options || {};
    options.authorizationURL = options.authorizationURL || 'https://quizlet.com/authorize';
    options.tokenURL = options.tokenURL || 'https://api.quizlet.com/oauth/token';
    options.scope = options.scope || ['read', 'write_set', 'write_group'];
    options.scopeSeparator = options.scopeSeparator || ' ';
    options.passReqToCallback = true;
    options.state = true;
    OAuth2Strategy.call(this, options, verify);
    this.name = 'quizlet';
}

util.inherits(QuizletStrategy, OAuth2Strategy);

QuizletStrategy.prototype.authenticate = function (req, options) {
    options = options || {};
    var self = this;

    if (req.query && req.query.error) {
        if (req.query.error == 'access_denied') {
            return this.fail({
                message: req.query.error_description
            });
        } else {
            return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
        }
    }

    var callbackURL = options.callbackURL || this._callbackURL;
    if (callbackURL) {
        var parsed = url.parse(callbackURL);
        if (!parsed.protocol) {
            // The callback URL is relative, resolve a fully qualified URL from the
            // URL of the originating request.
            callbackURL = url.resolve(utils.originalURL(req, {
                proxy: this._trustProxy
            }), callbackURL);
        }
    }

    if (req.query && req.query.code) {
        var code = req.query.code;

        if (this._state) {
            if (!req.session) {
                return this.error(new Error('QuizletStrategy requires session support when using state. Did you forget app.use(express.session(...))?'));
            }

            var key = this._key;
            if (!req.session[key]) {
                return this.fail({
                    message: 'Unable to verify authorization request state.'
                }, 403);
            }
            var state = req.session[key].state;
            if (!state) {
                return this.fail({
                    message: 'Unable to verify authorization request state.'
                }, 403);
            }

            delete req.session[key].state;
            if (Object.keys(req.session[key]).length === 0) {
                delete req.session[key];
            }

            if (state !== req.query.state) {
                return this.fail({
                    message: 'Invalid authorization request state.'
                }, 403);
            }
        }

        var params = this.tokenParams(options);
        params.grant_type = 'authorization_code';
        params.redirect_uri = callbackURL;

        this._oauth2.getOAuthAccessToken(code, params,
            function (err, accessToken, refreshToken, params) {
                if (err) {
                    return self.error(self._createOAuthError('Failed to obtain access token', err));
                }

                self._params = params;
                self._loadUserProfile(accessToken, function (err, profile) {
                    if (err) {
                        return self.error(err);
                    }

                    function verified(err, user, info) {
                        if (err) {
                            return self.error(err);
                        }
                        if (!user) {
                            return self.fail(info);
                        }
                        self.success(user, info);
                    }

                    try {
                        if (self._passReqToCallback) {
                            var arity = self._verify.length;
                            if (arity == 6) {
                                self._verify(req, accessToken, refreshToken, params, profile, verified);
                            } else { // arity == 5
                                self._verify(req, accessToken, refreshToken, profile, verified);
                            }
                        } else {
                            var arity = self._verify.length;
                            if (arity == 5) {
                                self._verify(accessToken, refreshToken, params, profile, verified);
                            } else { // arity == 4
                                self._verify(accessToken, refreshToken, profile, verified);
                            }
                        }
                    } catch (ex) {
                        return self.error(ex);
                    }
                });
            }
        );
    } else {
        var params = this.authorizationParams(options);
        params.response_type = 'code';
        params.redirect_uri = callbackURL;
        var scope = options.scope || this._scope;
        if (scope) {
            if (Array.isArray(scope)) {
                scope = scope.join(this._scopeSeparator);
            }
            params.scope = scope;
        }
        var state = options.state;
        if (state) {
            params.state = state;
        } else if (this._state) {
            if (!req.session) {
                return this.error(new Error('QuizletStrategy requires session support when using state. Did you forget app.use(express.session(...))?'));
            }

            var key = this._key;
            state = uid(24);
            if (!req.session[key]) {
                req.session[key] = {};
            }
            req.session[key].state = state;
            params.state = state;
        }

        var location = this._oauth2.getAuthorizeUrl(params);
        this.redirect(location);
    }
};

QuizletStrategy.prototype.userProfile = function (accessToken, done) {
    var oauth2 = this._oauth2;
    var userProfileURL = 'https://api.quizlet.com/2.0/users/' + this._params.user_id;

    oauth2.get(userProfileURL, accessToken, function (err, body, res) {
        if (err) {
            return done(new InternalOAuthError('Failed to get user profile!', err));
        }

        try {
            var json = JSON.parse(body);
            delete json.studied;
            delete json.favorite_sets;
            delete json.sets;

            var profile = _.clone(json);
            profile.provider = 'quizlet';
            profile._raw = body;
            profile._json = json;
            done(null, profile);
        } catch (ex) {
            done(ex);
        }
    });
};

/**
 * Expose `QuizletStrategy`.
 */
module.exports = QuizletStrategy;