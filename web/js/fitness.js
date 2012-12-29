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

    getNextUserID : function(callback) {
        var UserIDCounter = StackMob.Model.extend({ schemaName: 'user_id_counter' });
        var counter = new UserIDCounter({'user_id_counter_id' : '36eff9a9037b445185a05a1bc4ffc766'});
        counter.fetch({
            success: function(model) {
                console.debug(model.toJSON());
                model.incrementOnSave('current_id', 1); // the field will be incremented by 1
                model.save({}, {
                    success: function(model) {
                        console.debug(model.toJSON());
                        if (typeof callback === "function") {
                            if (model.attributes && model.attributes.current_id) {
                                callback(true, model.attributes.current_id);
                            }
                            else {
                                callback(false);
                            }
                        }

                    },
                    error: function(model, response) {
                        // response['error'] is the container for our error message
                        console.debug("Aww...why did you fail on me?! " + response['error']);
                        if (typeof callback === "function") {
                            callback(false);
                        }
                    }
                });
            },
            error: function(model, response) {
                console.debug(response);
                if (typeof callback === "function") {
                    callback(false);
                }
            }
        });
    },

    getFitbitRequestToken : function(userID) {
        StackMob.customcode('fetch_fitbit_request_token', {'stackmob_user_id' : userID}, {
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
                localStorage.setItem('fitbit_user_id', jsonResult.fitbit_user_id);
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

    getFitbitUser : function(callback) {
        var access_token = localStorage.getItem("access_token");
        var access_token_secret = localStorage.getItem("access_token_secret");
        var fitbit_user_id = localStorage.getItem("fitbit_user_id");

        var results;
        StackMob.customcode('fetch_fitbit_user', {"access_token" : access_token, "access_token_secret" : access_token_secret, "fitbit_user_id" : fitbit_user_id}, 'GET', {
            success: function(jsonResult) {
                results = 'got user!<br/>\n';
                var userInfoResponse = jsonResult['userInfoJson'];
                var user = JSON.parse(userInfoResponse)['user'];

                for (var key in user) {
                    results += key + ": " + user[key] + '<br>\n';
                }
                $('#results').html(results);
                if (typeof callback === "function") {
                    callback(true, user);
                }
            },

            error: function(jsonResult) {
                results = 'call failed, no user info returned<br/>\n';
                for (var key in jsonResult) {
                    results += key + ": " + jsonResult[key] + '<br>\n'
                }
                $('#results').html(results);
                if (typeof callback === "function") {
                    callback(false, jsonResult);
                }
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

    saveUserToStackmob : function(success, fitbitUser) {
        //var User = StackMob.Model.extend({ schemaName: 'user' });
        //var user = new User(fitbitUser);
        //var user = new StackMob.User(fitbitUser);
        if (!success) {
            $('#results').html('failed to fetch fitbit user');
            return;
        }

        fitbitUser.username = fitness.stackmobUserID.toString();
        localStorage.setItem('display_name', fitbitUser.displayName);

        var user = new StackMob.User(fitbitUser);
        console.debug(user.toJSON());
        user.create({
            success: function(model) {
                console.debug('user object is saved, todo_id: ');// + model.get('todo_id') + ', title: ' + model.get('title'));
                $('#results').html('user saved to datastore!');

            },
            error: function(model, response) {
                console.debug(response);
                $('#results').html('failed to save user to datastore');
            }
        });    },

    bindEvents : function() {
        var that = this;
        $('#authorize_link').on('click', function() {
            that.getFitbitRequestToken();
        });
        $('#get_user_link').on('click', function() {
            if (fitness.stackmobUserID) {
                that.getFitbitUser(that.saveUserToStackmob);
            }
            else {
                that.getNextUserID(function(result, currentUserID) {
                    if (result) {
                        fitness.stackmobUserID = currentUserID;
                        localStorage.setItem('stackmob_user_id', currentUserID);
                        that.getFitbitUser(that.saveUserToStackmob);
                    }
                    else {
                        $('#results').html('Failed to get next StackMob user ID');
                    }
                });
            }
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

        this.stackmobUserID = localStorage.getItem("stackmob_user_id");
        this.displayName = localStorage.getItem("display_name");
        if (this.stackmobUserID && this.displayName) {
            $('#authorize_link').hide();
            $('#get_user_link').hide();
            $('#results').html('Hello ' + this.displayName + '!');
        }
        else {
            if (window.location.href.indexOf('oauth_token') !== -1) {
                $('#authorize_link').hide();
                this.getFitbitAccessToken();
            }
        }
    }
};

$(function() {
    fitness.init();
});
