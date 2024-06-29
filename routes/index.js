var express = require('express');
var router = express.Router();
let userModel = require("./users");
let flash = require("connect-flash");
const passport = require('passport');
let localStrategy = require("passport-local");
let nodemailer = require('nodemailer');
let crypto = require('crypto');
require('dotenv').config(); // Load environment variables
let { Resend } = require("resend");

passport.use(new localStrategy(userModel.authenticate()));

/* GET home page. */
router.get('/', function (req, res, next) {
  res.render('index', { title: 'Express', error: req.flash('error') });
});

router.get('/login', function (req, res, next) {
  res.render('login', { error: req.flash('error') });
});

router.get('/register', function (req, res, next) {
  res.render('register', { error: req.flash('error') });
});

router.get('/verifyotp', function (req, res, next) {
  res.render('verifyotp', { error: req.flash('error') });
});


router.get('/profile', isLoggedIn, async function(req, res, next) {
  try {
    let user = await userModel.findOne({ email: req.user.email });
    if (user) {
      res.render('profile', { title: 'Express', user: user });
    } else {
      res.status(404).send('User not found');
    }
  } catch (error) {
    next(error);
  }
});

router.get('/unauthorized', function (req, res, next) {
  res.render('unauthorized', { error: 'You are not authorized to view this page.' });
});

router.post("/login", passport.authenticate("local", {
  successRedirect: "/profile",
  failureRedirect: "/login",
  failureFlash: true
}));

router.get('/logout', function(req, res, next){
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated() && req.user && req.user.isVerified) {
    return next();
  }
  res.redirect("/verifyotp");
}

router.post("/register", function(req, res, next) {
  let otp = Math.floor(100000 + Math.random() * 900000);
  let userdata = new userModel({
    username: req.body.username,
    email: req.body.email,
    password: req.body.password,
    otp: otp,
    otpExpires: Date.now() + 3600000 // 1 hour
  });

  userModel.register(userdata, req.body.password)
  .then(function(registereduser) {
    // Send OTP email
    let transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    let mailOptions = {
      from: process.env.EMAIL_USER,
      to: registereduser.email,
      subject: 'Email Verification',
      text: `Your OTP for email verification is ${otp}`
    };

    transporter.sendMail(mailOptions, function(error, info){
      if (error) {
        return console.log(error);
      }
      console.log('Email sent: ' + info.response);
    });

    res.redirect('/verifyotp');
  })
  .catch(function(err) {
    console.error("Error during registration:", err);
    req.flash('error', 'Registration failed');
    res.redirect('/register');
  });
});


router.post('/verifyotp', function(req, res, next) {
  console.log("Received email: ", req.body.email);
  console.log("Received OTP: ", req.body.otp);

  userModel.findOne({ email: req.body.email, otp: req.body.otp, otpExpires: { $gt: Date.now() } })
  .then(function(user) {
    if (!user) {
      console.log("No user found or OTP expired");
      return res.redirect('/verifyotp');
    }
    user.isVerified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    user.save().then(function() {
      console.log("User verified and saved");
      req.login(user, function(err) { // Log the user in after verification
        if (err) {
          console.error("Error logging in user:", err);
          return next(err);
        }
        res.redirect('/profile');
      });
    });
  })
  .catch(function(err) {
    console.error("Error during verification:", err);
    return next(err);
  });
});


// Forgot password route
router.get('/forgot', function(req, res) {
  res.render('forgot');
});

router.post('/forgot', async function(req, res, next) {
  try {
    const email = req.body.email;
    const user = await userModel.findOne({ email });
    if (!user) {
      req.flash('error', 'No user found with that email');
      return res.redirect('/forgot');
    }

    // Generate OTP
    const otp = crypto.randomBytes(3).toString('hex').toUpperCase();
    user.otp = otp;
    user.otpExpires = Date.now() + 3600000; // 1 hour expiration

    await user.save();

    // Send OTP email
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: false, // Adjust based on your email provider
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      }
    });

    const mailOptions = {
      from: '"Your App Name" <your_email@example.com>',
      to: user.email,
      subject: 'Your OTP for password reset',
      text: `Your OTP for resetting your password is ${otp}. It will expire in 1 hour.`
    };

    transporter.sendMail(mailOptions, function(error, info){
      if (error) {
        console.error("Error sending email:", error);
        req.flash('error', 'Error sending OTP. Please try again later.');
        return res.redirect('/forgot');
      } else {
        req.flash('success', 'OTP sent to your email. Please check your inbox.');
        res.redirect('/reset');
      }
    });
  } catch (err) {
    console.error("Error during forgot password:", err);
    return next(err);
  }
});

// Reset password route
router.get('/reset', function(req, res) {
  res.render('reset');
});

router.post('/reset', async function(req, res, next) {
  try {
    const { email, otp, password } = req.body;
    const user = await userModel.findOne({ email, otp, otpExpires: { $gt: Date.now() } });

    if (!user) {
      req.flash('error', 'No user found or OTP expired');
      return res.redirect('/forgot');
    }

    user.setPassword(password, async function(err) {
      if (err) {
        console.error("Error setting password:", err);
        req.flash('error', 'Error resetting password. Please try again.');
        return res.redirect('/reset');
      } else {
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();

        req.login(user, function(err) {
          if (err) {
            console.error("Error logging in after password reset:", err);
            req.flash('error', 'Error logging in. Please try again.');
            return res.redirect('/reset');
          } else {
            req.flash('success', 'Password reset successfully. Welcome back!');
            res.redirect('/profile');
          }
        });
      }
    });
  } catch (err) {  
    console.error("Error during password reset:", err);
    return next(err);
  }
}); 


module.exports = router;
