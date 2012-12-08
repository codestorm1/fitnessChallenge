"use strict";
var fitness = fitness || {

    getQueryVariable: function (url, key) {
        var query = url.split("?");
        if (query.length > 1) {
            var vars = query[1].split("&");
            for (var i = 0; i < vars.length; i++) {
                var pair = vars[i].split("=");
                if (pair[0] == key) {
                    return pair[1];
                }
            }
        }
        return null;
    },

    getFitbitRequestToken : function() {
        StackMob.customcode('fetch_fitbit_request_token', {}, {
            success: function(jsonResult) {
                //jsonResult is the JSON object: { "msg": "Hello, world!" }
                localStorage.setItem('request_token', jsonResult.oauth_token);
                localStorage.setItem('request_token_secret', jsonResult.oauth_token_secret);
                window.location.href = 'http://www.fitbit.com/oauth/authorize?oauth_token=' + jsonResult.oauth_token;
//                  alert(jsonResult.oauth_token);
            },

            error: function(failure) {
                alert('error!');
                //doh!
            }
        });
    },

    getFitbitAccessToken : function() {
        var request_token = localStorage.getItem("request_token");
        var request_token_secret = localStorage.getItem("request_token_secret");
        var oauth_verifier = this.getQueryVariable(window.location.href, 'oauth_verifier');

        var pos = oauth_verifier.length - 1;
        if (oauth_verifier[pos] === '/') { // stackmob mistakenly adds a slash to the URL, so remove it
            oauth_verifier = oauth_verifier.substring(0, pos).replace('#',''); // also kill a # if there is one
        }
        var results;
        StackMob.customcode('fetch_fitbit_access_token', {"request_token" : request_token, "request_token_secret" : request_token_secret, "oauth_verifier" : oauth_verifier}, 'GET', {
            success: function(jsonResult) {
                localStorage.setItem('access_token', jsonResult.oauth_token);
                localStorage.setItem('access_token_secret', jsonResult.oauth_token_secret);
                results = 'got tokens!<br/>\n';
                for (var key in jsonResult) {
                    results += key + ": " + jsonResult[key] + '<br>\n';
                }
                $('#results').html(results);
            },

            error: function(jsonResult) {
                results = 'call failed, no tokens, click the link to authorize<br/>\n';
                for (var key in jsonResult) {
                    results += key + ": " + jsonResult[key] + '<br>\n'
                }
                $('#results').html(results);
            }
//        StackMob.customcode('create_fitbit_user', {'request_token' : request_token, 'request_token_secret' : request_token_secret, 'oauth_verifier' : oauth_verifier}, 'POST', {
//            success: function(jsonResult) {
//                //jsonResult is the JSON object: { "msg": "Hello, world!" }
//                alert('weee!')
//            },
//
//            error: function(failure) {
//                alert('boo error!');
//                //doh!
//            }
        });

    },

    bindEvents : function() {
        var that = this;
        $('#authorize_link').on('click', function() {
            that.getFitbitRequestToken();
        });
    },

    init : function() {

        StackMob.init({
            appName: "fitnesschallenge",
            clientSubdomain: "twistedogregmailcom",
            publicKey: "ba025b72-92db-4681-9abb-231baca5a94d",
            apiVersion: 0
            });
        this.bindEvents();

        if (window.location.href.indexOf('oauth_token') !== -1) {
            this.getFitbitAccessToken();
        }
    }
};

$(function() {
    fitness.init();
});
