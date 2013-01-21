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

    getTemplateTarget: function (templateElement) {
        if (templateElement[0]) {
            return templateElement.data("target-element");
        }
    },

    renderTemplate: function (templateSelector, dto, doAppend, target) {
        var template = $(templateSelector);
        if (template[0]) {
            var html = Mustache.to_html(template.html(), dto || {});
            if (!target) {
                var targetSelector = template.data("target-element");
                target = $(targetSelector);
            }
            if (target[0]) {
                if (doAppend) {
                    target.append(html);
                }
                else {
                    target.html(html);
                }
                return targetSelector;
            }
        }
    },

    showMessage : function(message) {
        alert(message);
    },

    getNextUserID : function(callback) {
        var UserIDCounter = StackMob.Model.extend({ schemaName: 'user_id_counter' });
        var counter = new UserIDCounter({'user_id_counter_id' : '36eff9a9037b445185a05a1bc4ffc766'});
        counter.fetch({
            success: function(model) {
                model.incrementOnSave('current_id', 1); // the field will be incremented by 1
                model.save({}, {
                    success: function(model) {
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

    getFitbitRequestToken : function(userID, callback) {
        StackMob.customcode('fetch_fitbit_request_token', {'stackmob_user_id' : userID}, {
            success: function(tokens) {
                //jsonResult is the JSON object: { "msg": "Hello, world!" }
                localStorage.setItem('request_token', tokens.oauth_token);
                localStorage.setItem('request_token_secret', tokens.oauth_token_secret);
                if (typeof callback === "function") {
                    callback(true, tokens)
                }
            },
            error: function(data) {
                if (typeof callback === "function") {
                    callback(false, data)
                }
            }
        });
    },

    getFitbitAccessToken : function(callback, params) {
        var that = this;
        var requestToken = localStorage.getItem("request_token");
        var requestTokenSecret = localStorage.getItem("request_token_secret");

        var oauthVerifier = this.getQueryVariable(window.location.href, 'oauth_verifier');

        var pos = oauthVerifier.length - 1;
        if (oauthVerifier[pos] === '/') { // stackmob mistakenly adds a slash to the URL, so remove it
            oauthVerifier = oauthVerifier.substring(0, pos).replace('#',''); // also kill a # if there is one
        }
        var results;
        var params = {
            "request_token" : requestToken,
            "request_token_secret" : requestTokenSecret,
            "oauth_verifier" : oauthVerifier
        };

        StackMob.customcode('fetch_fitbit_access_token', params, 'GET', {
            success: function(accessTokenData) {
                localStorage.setItem('access_token', accessTokenData.oauth_token);
                localStorage.setItem('access_token_secret', accessTokenData.oauth_token_secret);
                localStorage.setItem('fitbit_user_id', accessTokenData.fitbit_user_id);
                localStorage.removeItem('request_token');
                localStorage.removeItem('request_token_secret');
                that.updateAppUserFromLocal();
                if (typeof callback === "function") {
                    callback(true, params, accessTokenData);
                }
            },

            error: function(jsonResult) {
                results = 'call failed, no tokens, click the link to authorize<br/>\n';
                for (var key in jsonResult) {
                    results += key + ": " + jsonResult[key] + '<br>\n'
                }
                $('#results').html(results);
                if (typeof callback === "function") {
                    callback(false, params, jsonResult);
                }
            }
        });
    },

    getFitbitUser : function(callback) {

        var results;
        var params = {
            "access_token" : this.user.accessToken,
            "access_token_secret" : this.user.accessTokenSecret,
            "fitbit_user_id" : this.user.fitbitUserID
        };
        StackMob.customcode('fetch_fitbit_user', params, 'GET', {
            success: function(jsonResult) {
                var userInfoResponse = jsonResult['userInfoJson'];
                var user = JSON.parse(userInfoResponse)['user'];
                if (typeof callback === "function") {
                    callback(true, user);
                }
            },

            error: function(errorData) {
                if (typeof callback === "function") {
                    callback(false, errorData);
                }
            }
        });
    },

    updateAppUserFromLocal : function() {
        this.user = this.user || {};
        this.user.stackmobUserID = localStorage.getItem('stackmob_user_id');
        this.user.fitbitUserID = localStorage.getItem("fitbit_user_id");
        this.user.accessToken = localStorage.getItem("access_token");
        this.user.accessTokenSecret = localStorage.getItem("access_token_secret");
        this.user.displayName = localStorage.getItem("display_name");
        return this.user;
    },

    saveUserToLocal : function(user) {
        localStorage.setItem('stackmob_user_id', user.stackmobUserID);
        localStorage.setItem('fitbit_user_id', user.fitbitUserID);
        localStorage.setItem('access_token', user.accessToken);
        localStorage.setItem('access_token_secret', user.accessTokenSecret);
        localStorage.setItem('display_name', user.displayName);
    },

    getFitbitFriends : function(stackmobUserID, callback) {

        var results;
        StackMob.customcode('fetch_fitbit_friends', {"stackmob_user_id" : stackmobUserID}, 'GET', {
            success: function(jsonResult) {
                results = 'got friends!<br/>\n';
                var friendsResponse = jsonResult['friendsJson'];
                var friends = JSON.parse(userInfoResponse)['friends'];

                var len = friends.length;
                var friend;
                for (var i = 0; i < len; i++) {
                    friend = friends[i];
                    for (var key in friend) {
                        results += key + ": " + friend[key] + '<br>\n';
                    }
                }
                $('#results').html(results);
                if (typeof callback === "function") {
                    callback(true, friends);
                }
            },

            error: function(jsonResult) {
                results = 'call failed, no friends returned<br/>\n';
                for (var key in jsonResult) {
                    results += key + ": " + jsonResult[key] + '<br>\n'
                }
                $('#results').html(results);
                if (typeof callback === "function") {
                    callback(false, jsonResult);
                }
            }
        });

    },

    lookupFitnessUser : function(email, password, callback) {
        var that = this;
        if (!email) {
            if (typeof callback === 'function') {
                callback(false, 'email address is required');
            }
            return;
        }
        var User = StackMob.Model.extend({ schemaName: 'user' });
        var Users = StackMob.Collection.extend({ model: User });
        var users = new Users();
        var q = new StackMob.Collection.Query();
        q.equals('email', email);
        if (password) {
            q.equals('fc_password', password);
        }
        users.query(q, {
            success: function(model) {
                if (model.models.length > 0 && model.models[0].attributes) {
                    if (typeof callback === 'function') {
                        callback(true, model.models[0].attributes);
                    }
                }
                else {
                    if (typeof callback === 'function') {
                        callback(false, model);
                    }
                }
            },
            error: function(response) {
                that.showMessage('query failed trying to get user ' + response);
                console.debug(response);
                if (typeof callback === 'function') {
                    callback(false, response);
                }
            }
        });
    },

    saveUserToStackmob : function(email, password, callback) {
        var that = this;
        //var User = StackMob.Model.extend({ schemaName: 'user' });
        //var user = new User(fitbitUser);

        this.lookupFitnessUser(email, password, function(success, data) {
            if (success) {
                that.showMessage('That email address is already in use');
                return;
            }
            that.getNextUserID(function(success, currentUserID) {
                if (success) {
                    var regInfo = {
                        "email" : email,
                        "password" : password,
                        "fc_password" : password,
                        "username" : currentUserID.toString()
                        };

                    var user = new StackMob.User(regInfo);
                    user.create({
                        success: function(model) {
                            console.debug('user object is saved');
                            fitness.user.stackmobUserID = currentUserID;
                            localStorage.setItem('stackmob_user_id', currentUserID);
                            callback(true, model);
                        },
                        error: function(model, response) {
                            console.debug(response);
                            callback(false, 'failed to save user to datastore');
                        }
                    });
                }
                else {
                    callback(false, 'Failed to get next StackMob user ID');
                }
            });
        });
    },

    updateWithFitbitUser : function(fitbitUser, callback) {

        delete fitbitUser.encodedId;
        var fields = fitbitUser;
        fields.access_token = this.user.accessToken;
        fields.access_token_secret = this.user.accessTokenSecret;
        fields.fitbit_user_id = this.user.fitbitUserID;

        var user = new StackMob.User({ username : this.user.stackmobUserID });
        user.save(fields, {
            success: function(model) {
                console.debug(model.toJSON());
                if (typeof callback === "function") {
                    callback(true, model);
                }
            },
            error: function(model, response) {
                console.debug(response);
                if (typeof callback === "function") {
                    callback(false, response);
                }
            }
        });
    },

    saveFriendsToStackmob : function(success, fitbitUser) {
        if (!success) {
            $('#results').html('can\'t save friends - failed to fetch friends');
            return;
        }

        fitbitUser.username = fitness.user.stackmobUserID.toString();
        fitbitUser.access_token = localStorage.getItem("access_token");
        fitbitUser.access_token_secret = localStorage.getItem("access_token_secret");
        fitbitUser.fitbit_user_id = localStorage.getItem("fitbit_user_id");

        var user = new StackMob.User(fitbitUser);
        user.create({
            success: function(model) {
                console.debug('user object is saved');
                $('#results').html('user saved to datastore!');

            },
            error: function(model, response) {
                console.debug(response);
                $('#results').html('failed to save user to datastore');
            }
        });
    },

    bindEvents : function() {
        var that = this;
        $('#get_friends_link').on('click', function() {
            if (that.user.stackmobUserID) {
                that.getFitbitFriends(that.saveFriendToStackmob);
            }
            else {
                $('#results').html('Create a StackMob user ID first');
            }
        });

        $('#register_submit').live('click', function() {
            var email = $("#register_email").val();
            var newPassword = $('#new_password').val();
            var confirmPassword = $('#confirm_password').val();
            if (newPassword !== confirmPassword) {
                that.showMessage("Passwords do not match");
                return;
            }
            that.saveUserToStackmob(email, newPassword, function(success, data) {
                if (success) {
                    window.location.href = '/#auth';
                }
                else {
                    that.showMessage('Failed to save user:\n' + data);
                }
            });
        });

        $('#login_submit').live('click', function() {
            var email = $("#email").val();
            var password = $('#password').val();
            that.lookupFitnessUser(email, password, function(success, data) {
                if (success) { // logged in
                    that.user.stackmobUserID = data.username;
                    that.user.accessToken = data.access_token;
                    that.user.accessTokenSecret = data.access_token_secret;
                    that.user.fitbitUserID = data.fitbit_user_id;
                    that.user.displayName = data.displayname;
                    that.saveUserToLocal(that.user);
                    window.location.href = '/#home';
                }
                else {
                    that.showMessage('login failed ' + data);
                }
            });
        });

        $(document).bind("mobileinit", function () {
            $.mobile.ajaxEnabled = false;
            $.mobile.linkBindingEnabled = false;
            $.mobile.hashListeningEnabled = false;
            $.mobile.pushStateEnabled = false;
        });

        $('div[data-role="page"]').live('pagehide', function (event, ui) {
            $(event.currentTarget).remove();
        });

    },

    init : function() {

        var that = this;
        this.updateAppUserFromLocal();
        StackMob.init({
            appName: "fitnesschallenge",
            clientSubdomain: "twistedogregmailcom",
            publicKey: "ba025b72-92db-4681-9abb-231baca5a94d",
            apiVersion: 0
            });
        this.bindEvents();

        this.AppRouter = Backbone.Router.extend({

            routes:{
                "" : "home",
                "login" : "login",
                "logout" : "logout",
                "home" : "home",
                "register" : "register",
                "auth" : "auth"

            },

            changePage : function (page) {
                return;
                $(page.el).attr('data-role', 'page');
                page.render();
                //$('#main').append($(page.el));
                $.mobile.changePage($(page.el), {changeHash:true});
            },

            home : function () {
                if (!that.user.stackmobUserID) {
                    this.changePage(new that.LoginView());
                    return;
                }

                this.changePage(new that.HomeView());
            },

            login : function() {
                this.changePage(new that.LoginView());
            },


            logout: function() {
                localStorage.clear();
                this.changePage(new that.LoginView());
            },

            register: function() {
                this.changePage(new that.RegisterView());
            },

            auth: function() {
                this.changePage(new that.AuthView());
            }

        });

        var that = this;
        this.LoginView = Backbone.View.extend({
            el: '#main',

            initialize: function() {
                this.render();
            },

            render: function() {
                var template = $('#login_template');
                this.$el.empty();
                this.$el.append(template.html());
                this.$el.trigger('create');
                $('.logout-link').hide();
                return this;
            }
        });

        this.HomeView = Backbone.View.extend({
            el: '#main',

            initialize: function() {
                this.render();
            },

            render: function() {
                if (window.location.href.indexOf('oauth_token') !== -1) {
                    that.getFitbitAccessToken(function(success) {
                        if (success) {
                            if (fitness.user.stackmobUserID) {
                                that.getFitbitUser(function(success, data) {
                                    if (success) {
                                        that.user.displayName = data.displayName;
                                        localStorage.setItem("display_name", data.displayName);
                                        that.user.fitbitUserID = data.encodedId;
                                        that.updateWithFitbitUser(data, function(success, data) {
                                            if (success) {
                                                window.location.href = '/#home';
                                            }
                                            else {

                                                that.showMessage('failed to update with fitbit info\n ' + data.error);
                                            }
                                        });
                                    }
                                    else {
                                        that.showMessage("failed to get Fitbit User: " + data);
                                        return;
                                    }
                                });
                            }
                        }
                        else {
                            that.showMessage("failed to get Fitbit access token");
                            return;
                        }
                    });
                    return;
                }
                var template = $('#home_template');
                var dto = {
                    "stackmobID" : fitness.user.stackmobUserID,
                    "displayName" : fitness.user.displayName
                };
                var html = Mustache.to_html(template.html(), dto);
                this.$el.empty();
                this.$el.append(html);

                if (!fitness.user.fitbitUserID) {
                    window.location.href = '/#auth';
                }
                $('.logout-link').show();

                this.$el.trigger('create');
                return this;
            }
        });

        this.RegisterView = Backbone.View.extend({
            el: '#main',

            initialize: function() {
                this.render();
            },

            render: function() {
                var template = $('#register_template');
                var dto = {
                    "stackmobID" : fitness.user.stackmobUserID,
                    "displayName" : fitness.user.displayName
                };
                var html = Mustache.to_html(template.html(), dto);
                this.$el.empty();
                this.$el.append(html);
                this.$el.trigger('create');
                $('.logout-link').hide();
                return this;
            }
        });

        this.AuthView = Backbone.View.extend({
            el: '#main',

            initialize: function() {
                this.render();
            },

            render: function() {
                $('#authorize_link').live('click', function() {
                    that.getFitbitRequestToken(fitness.user.stackmobUserID, function(success, data) {
                            if (success) {
                                window.location.href = 'http://www.fitbit.com/oauth/authorize?oauth_token=' + data.oauth_token;
                            }
                            else {
                                that.showMessage('Sorry, could not authorize with fitbit.\n  Failed to get fitbit request token');
                            }
                        }
                    );
                });
                var template = $('#auth_template');
//                var html = Mustache.to_html(template.html(), dto);
                this.$el.empty();
                this.$el.append(template.html());
                $('.logout-link').show();
                this.$el.trigger('create');
                return this;
            }
        });

        var router = new this.AppRouter();
        Backbone.history.start();
//        if (this.user.stackmobUserID && this.displayName) {
//            this.homeView = new this.HomeView();
//        }
//        else {
//        }

    }
};

$(function() {
    fitness.init();
});
