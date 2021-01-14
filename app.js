require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.set('useUnifiedTopology', true);
mongoose.connect("mongodb://localhost:27017/paymeeDB", {useNewUrlParser: true});

const Schema = mongoose.Schema

const userSchema = new Schema ({
  fname: String,
  lname: String,
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

///////////////////////////////////////////////////////////////////////////////

app.route("/")
.get(function(req,res){
  res.render("home");
});

app.route("/register")
.get(function(req,res){
  res.render("register")
})
.post(function(req,res){
  User.register({username: req.body.username, lname: req.body.lname,
  fname: req.body.fname}, req.body.password, function(err, user){
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/paymee");
      });
    }
  });
})

app.route("/signin")
.get(function(req,res){
  res.render("signin");
})
.post(function(req, res){
  const user = new User({
    email: req.body.username,
    password: req.body.password
  });
  req.login(user, function(err){
    if (err) {
      console.log(err);
      res.render("/signin")
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/paymee");
      });
    }
  });
});


app.get("/paymee", function(req, res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if (err){
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("paymee", {usersWithSecrets: foundUsers});
      }
    }
  });
});


app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/signin");
  }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;
  User.findById(req.user.id, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/paymee");
        });
      }
    }
  });
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/sigin" }),
  function(req, res) {
    // Successful authentication, redirect to paymee.
    res.redirect("/paymee");
  });

  app.get("/logout", function(req, res){
    req.logout();
    res.redirect("/");
  });

app.listen(3000, function() {
  console.log("Server started on port 3000.");
});
