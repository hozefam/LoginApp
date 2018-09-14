var express = require("express");
var router = express.Router();
var passport = require("passport");
var localStrategy = require("passport-local").Strategy;

var User = require("../models/user");

router.get("/register", (req, res) => {
  res.render("register");
});

router.get("/login", (req, res) => {
  res.render("login");
});

router.post("/register", (req, res) => {
  const { name, email, password, password2, username } = req.body;

  req.checkBody("name", "Name is required").notEmpty();
  req.checkBody("email", "Email is required").notEmpty();
  req.checkBody("email", "Email is not valid").isEmail();
  req.checkBody("username", "Username is required").notEmpty();
  req.checkBody("password", "Password is required").notEmpty();
  req
    .checkBody("password2", "Passwords do not match")
    .equals(req.body.password);

  var errors = req.validationErrors();

  if (errors) {
    res.render("register", { errors });
  } else {
    var newUser = new User({
      name,
      email,
      username,
      password
    });

    User.createUser(newUser, (err, user) => {
      if (err) {
        throw err;
      }
      console.log(user);
    });

    req.flash("success_msg", "You are registered and can now login");
    res.redirect("/users/login");
  }
});

passport.use(
  new localStrategy(function(username, password, done) {
    User.getUserByUsername(username, (err, user) => {
      if (err) throw err;
      if (!user) {
        return done(null, false, { message: "Unknown User" });
      }

      User.comparePassword(password, user.password, (err, isMatch) => {
        if (err) throw err;
        if (isMatch) {
          return done(null, user);
        } else {
          console.log(isMatch);
          return done(null, false, { message: "Invalid password" });
        }
      });
    });
  })
);

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});

router.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/users/login",
    failureFlash: true
  }),
  function(req, res) {
    res.redirect("/");
  }
);

router.get("/logout", (req, res) => {
  req.logOut();
  req.flash("success_msg", "You are logged out");
  res.redirect("/users/login");
});

module.exports = router;
