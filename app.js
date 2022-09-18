require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose"); // PLP package will salt and hash the password
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
  secret: "Our little secret.", //any string
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
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

app.get("/", function(req, res){
  res.render("home");
});

app.route("/auth/google")
  .get(passport.authenticate("google", {
    scope: ["profile"]
}));

app.route("/auth/google/secrets")
  .get(passport.authenticate("google", {failureRedirect: "/login"}), function(req, res){
    res.redirect("/secrets");
});

app.get("/secrets", function(req, res){
  User.find({"secrets": {$ne: null}}, function(err, foundUsers){
    if(err){
      console.log(err);
    } else {
      if(foundUsers){
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
      res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;
  User.findById(req.user.id, function(err, foundUser){
    if(err){
      console.log(err);
    } else {
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets")
        });
      }
    }
  });
});

app.get("/logout", function(req, res){
  req.logout(function(err){
    if (err)
    {
      console.log(err);
    }
  res.redirect("/");
  });
});

app.route("/register")
  .get(function(req, res){
    res.render("register");
  })
  .post(function(req, res){
    if(req.body.password === req.body.cpassword){
      User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
          console.log(err);
          res.redirect("/register");
        } else {
          passport.authenticate("local")(req, res, function(){  //triggers only when authentication was successful and managed to setup a cookie, saved login sessions
            res.redirect("/secrets");
          });
        }
      });
    } else {
      res.redirect("/register");
    }
  });

app.route("/login")
  .get(function(req, res){
    res.render("login");
  })
  .post(function(req, res){
    const user = new User({
      username: req.body.username,
      password: req.body.password,
    });
    req.login(user, function(err){
      if(err){
        if(password !== req.body.password){
          res.write("The entered password or email is wrong. Plese check and try again");
          res.redirect("/login");
        }
      } else {
        passport.authenticate("local")(req, res, function(){ //passport package function to authenticate user
          res.redirect("/secrets");
        });
      }
    });
  });

app.listen(3000, function(req, res){
  console.log("The server has started on port 3000");
});
