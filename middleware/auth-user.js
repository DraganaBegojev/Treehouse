'use strict';

const auth = require('basic-auth');
const bcrypt = require('bcrypt');
const { User } = require('../models/user');

// Middleware to authenticate the request using Basic Authentication.

exports.authenticateUser = async (req, res, next) => {
    let message;  // Variable to hold the message to the user
    // Parse the user's credentials from the Authorization header.
    const credentials = auth(req);


 
     // by their username (i.e. the user's "key"
     // from the Authorization header).
     if (credentials) {   // If the user's credentials are available...
        const user = await User.findOne({ where: { username: credentials.name } });     // Attempt to retrieve the user from the data store
        if (user) {   // If a user was successfully retrieved from the data store...
            const authenticated = bcrypt      // Use the bcrypt npm package to compare the user's password
                .compareSync(credentials.pass, user.confirmedPassword);
            if (authenticated) {   // If the passwords match...
                console.log(
                    `Authentication successful for username: ${user.username}`
                );
                req.currentUser = user;   // Store the retrieved user object on the request object
            } else {   // If the passwords do not match...
                message = `Authentication failure for username: ${user.username}`;
            }
        } else {   // If a user was not found...
            message = `User not found for username: ${credentials.name}`;
        }
     } else {   // If the user's credentials are not available...
        message = 'Auth header not found';
     }

     if (message) {   // If user authentication failed...
        console.warn(message);
        res.status(401).json({ message: 'Access Denied' });   // Return a response with a 401 Unauthorized HTTP status code.
     } else {   // Or if user authentication succeeded...
        next();   // Call the next() method
    }
};