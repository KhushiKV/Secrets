//jshint esversion:6

require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
//const md5 = require("md5");
// const encrypt = require("mongoose-encryption");

const app =express();
app.set("view engine","ejs");
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));
app.use(session({
  secret: "ourlittlesecretgoeshere",
  resave:false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());



mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser:true,useUnifiedTopology:true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//userSchema.plugin(encrypt,{secret: process.env.SECRET,encryptedFields:['password']});
const User = new mongoose.model("User",userSchema);


passport.use(User.createStrategy());
passport.serializeUser(function(user,done){done(null,user)});
passport.deserializeUser(function(user,done){done(null,user)});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));




app.get("/",function(req,res){
  res.render("home");
})

app.get("/login",function(req,res){
  res.render("login");
})

app.get("/register",function(req,res){
  res.render("register");
})

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.post("/register",function(req,res){
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash
  //     //password: md5(req.body.password)
  //   });
  //   newUser.save(function(err){
  //     if(err) console.log(err);
  //     else {
  //       res.render("secrets");
  //     }
  //   });
  // });

  User.register({username: req.body.username}, req.body.password, function(err,user){
    if(err){
      console.log(err);
      res.redirect("register");
    }
    else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      })
    }
  })
});

app.post("/login",function(req,res){
  // const enteredEmail= req.body.username;
  // const enteredPassword= req.body.password;//md5(req.body.password);
  // User.findOne({email: enteredEmail},function(err,foundUser){
  //   if(!err){
  //     if(foundUser){
  //       bcrypt.compare(enteredPassword, foundUser.password, function(err, result) {
  //        if(!err){
  //        if(result === true)
  //        res.render("secrets");}
  //        else {console.log(err);}
  //       });
  //       // if(foundUser.password === enteredPassword){
  //       //   res.render("secrets");
  //       }
  //     }
  // })

  const user = new User({
    email: req.body.username,
    password: req.body.password
  });
  req.login(user,function(err){
    if(err){
      console.log(err);
      res.redirect("/login");
    }
    else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      })
    }
  })



});


app.get("/secrets",function(req,res){
  if(req.isAuthenticated()){
    User.find({secret: {$ne: null}}, function(err,foundUsers){
      if(err){
        console.log(err);
      }
      else
      {
        if(foundUsers){
          res.render("secrets",{userSecretList: foundUsers});
        }
      }
    })
  }
  else{
    res.redirect("/login");
  }
});

app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
});

app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }
  else{
    res.redirect("/login");
  }
});

app.post("/submit",function(req,res){
  const submittedSecret = req.body.secret;
  User.findById(req.user._id, function(err, foundUser){
    if(!err){
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
                  res.redirect("/secrets");
        });
      }
    }
    else{
      console.log(err);
    }
  })
})



app.listen(3000,function(){
  console.log("successfully started the server!");
})
