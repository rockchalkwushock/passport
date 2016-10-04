// ##########################
// #### Required Modules ####
// ##########################
var express = require('express');
var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var User = require('./user-model');
var bcrypt = require('bcryptjs');
var passport = require('passport');
var BasicStrategy = require('passport-http').BasicStrategy;

// Initializing the app variable to call Express.js Module.
var app = express();

// Initializing the jsonParser variable to call Body-Parser Module
var jsonParser = bodyParser.json();

// ########################
// ####### Passport #######
// ########################


// Calling Express Module to use Passport Module's initialize method.
app.use(passport.initialize());

// Creating new instance of BasicStrategy
var strategy = new BasicStrategy(function(username, password, callback) {
    User.findOne({  // Find the username called by user.
        username: username
    }, function (err, user) {
        if (err) {
            callback(err);
            return;
        }

        if (!user) { // if no username exists in db call error.
            return callback(null, false, {
                message: 'Incorrect username.'
            });
        }
        // Call for validation of a valid username's password by passing the
        // input password through validatePassword method.
        user.validatePassword(password, function(err, isValid) {
            if (err) {
                return callback(err);
            }

            if (!isValid) { // if not valid password in db for specific username call error.
                return callback(null, false, {
                    message: 'Incorrect password.'
                });
            }
            return callback(null, user);
        });
    });
});

// Calling Passport Module to use the object strategy.
passport.use(strategy);

// ##########################################
// ####### GET Request using Passport #######
// ##########################################

app.get('/hidden', passport.authenticate('basic', {session: false}), function(req, res) {
    res.json({
        message: 'Luke... I am your father'
    });
});

// ############################
// ####### POST Request #######
// ############################

app.post('/users', jsonParser, function(req, res) {

  // ###############################
  // ####### Body Validation #######
  // ###############################

    if (!req.body) {
        return res.status(400).json({
            message: "No request body"
        });
    }

    if (!('username' in req.body)) {
        return res.status(422).json({
            message: 'Missing field: username'
        });
    }

    var username = req.body.username;

    if (typeof username !== 'string') {
        return res.status(422).json({
            message: 'Incorrect field type: username'
        });
    }

    username = username.trim();

    if (username === '') {
        return res.status(422).json({
            message: 'Incorrect field length: username'
        });
    }

    if (!('password' in req.body)) {
        return res.status(422).json({
            message: 'Missing field: password'
        });
    }

    var password = req.body.password;

    if (typeof password !== 'string') {
        return res.status(422).json({
            message: 'Incorrect field type: password'
        });
    }

    password = password.trim();

    if (password === '') {
        return res.status(422).json({
            message: 'Incorrect field length: password'
        });
    }

    var user = new User({
        username: username,
        password: password
    });

    // ####################################
    // ####### Hashing using bcrypt #######
    // ####################################

    bcrypt.genSalt(10, function(err, salt) {
        if (err) {
            return res.status(500).json({
                message: 'Internal server error'
            });
        }

        bcrypt.hash(password, salt, function(err, hash) {
            if (err) {
                return res.status(500).json({
                    message: 'Internal server error'
                });
            }

            var user = new User({
                username: username,
                password: hash
            });

            user.save(function(err) {
                if (err) {
                    return res.status(500).json({
                        message: 'Internal server error'
                    });
                }

                return res.status(201).json({});
            });
        });
    });
});

// ##############################
// ####### Listen Request #######
// ##############################

mongoose.connect('mongodb://localhost/auth').then(function() {
    app.listen(process.env.PORT || 8000);
});
