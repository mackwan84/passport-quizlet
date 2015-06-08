/**
 * Module dependencies.
 */
var util = require('util'),
    OAuth2Strategy = require('passport-oauth2').Strategy,
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

QuizletStrategy.prototype.userProfile = function (accessToken, done) {
    var oauth2 = this._oauth2;
    var userProfileURL = 'https://api.quizlet.com/2.0/users/' + this._accessTokenResults.user_id;

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
 * Expose `Strategy`.
 */
module.exports = QuizletStrategy;