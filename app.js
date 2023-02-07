//jshint esversion:6
require('dotenv').config();
const express               = require('express');
const session               = require('express-session');
const bodyParser            = require('body-parser');
const ejs                   = require('ejs'); 
const mongoose              = require('mongoose');
const passport              = require('passport');
const passportLocalMongoose = require('passport-local-mongoose')
const GoogleStrategy        = require('passport-google-oauth20');
const FacebookStrategy      = require('passport-facebook');
const findOrCreate          = require('mongoose-findorcreate');

const GOOGLE_CLIENT_ID      = process.env.GOOGLE_CLIENT_ID;
const FACEBOOK_APP_ID       = process.env.FACEBOOK_CLIENT_ID;
const GOOGLE_CLIENT_SECRET  = process.env.GOOGLE_CLIENT_SECRET;
const FACEBOOK_APP_SECRET   = process.env.FACEBOOK_CLIENT_SECRET;
const PASSPORT_LOCAL_SECRET = process.env.SECRET

const app = express();
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended:true}));
app.use(session({
    secret:PASSPORT_LOCAL_SECRET,
    resave:false,
    saveUninitialized:false,

}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.set('strictQuery',false);
mongoose.connect("mongodb://localhost:27017/userDB")

const userSchema = new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    facebookId:String,
    secrets:String
})

userSchema.plugin(passportLocalMongoose,{usernameUnique:false});

userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);


passport.use(User.createStrategy());
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.name });
    });
  });
  
passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
 });
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({googleId: profile.id}, function (err, user) {
      return cb(err, user);
    });
  }
));
passport.use(new FacebookStrategy({
    clientID: FACEBOOK_APP_ID,
    clientSecret: FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));




//get requests


app.get("/", (req,res) =>{
    console.log("[+]GET REQUEST Received on port 3000  /home");
    res.render("home")
})
app.get("/auth/google",passport.authenticate("google", {scope:["profile"]}));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/auth/facebook',passport.authenticate('facebook'));
app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  }); 


app.get("/login", (req,res) =>{
    console.log("[+]GET REQUEST Received on port 3000  /login");
    res.render("login")
})

app.get("/register", (req,res) =>{
    console.log("[+]GET REQUEST Received on port 3000  /register");
    res.render("register")
})
app.get("/secrets", (req,res) =>{   
    User.find({"secrets":{$ne:null}}, (err,foundUsers) =>{
        if(err){
            console.log(err);
        }
        else{
            if(foundUsers){
                res.render("secrets",{usersSecrets:foundUsers})
            };
            
        };
    });
})
app.get("/logout",(req,res)=>{
    req.logout({keepSessionInfo:false},(err)=>{
        if(err){
            console.log(err)
        }
        else{
            res.redirect("/");  
        }
    });
    
});
app.get("/submit",(req,res)=>{
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    }
})



///post requests 

app.post("/register",(req,res) =>{
    User.register({username:req.body.username}, req.body.password, (err,user) =>{
        if(err){
            console.log(err);
            res.redirect("/register");

        }else{
            passport.authenticate("local")(req,res,()=>{
                res.redirect("/secrets");
            })
        }
    })

});
app.post("/login",(req,res) =>{
    const user = new User({
        username:req.body.username,
        password:req.body.password
    });
    req.login(user,(err) =>{
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local",(err,authUser) =>{
                if(err){
                    console.log(err);

                }
                else{
                    if(authUser){
                        req.login(user,(err)=>{
                            res.redirect("/secrets");
                        });
                    }
                    else{
                        res.redirect("/login");
                    }
                }
            })(req,res);
        }
    })
});
app.post("/submit",(req,res)=>{
    console.log("[+]POST REQUEST Received on port 3000 /submit");
    const submittedSecret = req.body.secret;
    const userId = req.user.id;

    User.findById(userId,(err,foundUser)=>{
        if(err){
            console.log(err);
        }
        else{
            if(foundUser){
                foundUser.secrets = submittedSecret;
                foundUser.save(()=>{
                    res.redirect("/secrets");
                })
            }
        }
    })
})

app.listen(3000,()=>{
    console.log("[+]Listening on port 3000");
})
