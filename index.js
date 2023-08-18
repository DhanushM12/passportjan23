const express = require('express');
const app = express();
const port =8080;
const passport = require('passport');
const session = require('express-session')
const initialize = require('./config/passportLocal');


const users = []; // array of objects
initialize(passport,
    email => users.find(user => user.email === email),
    id => users.find(user => user.id === id)
    )

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));

app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false,
}))

app.use(passport.initialize());

app.use(passport.session());

app.get('/', checkAuthenticated, (req, res) => {
    res.render('index')
})

app.get('/login',checkNotAuthenticated, (req, res) => {
    res.render('login')
})

app.get('/register',checkNotAuthenticated, (req, res) => {
    res.render('register')
})

function checkAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return next();
    }
    return res.redirect('/login')
}

function checkNotAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return res.redirect('/');
    }
    return next();
}

app.listen(port, function(err){
    if(err){
        console.log(`Error in running the server: ${err}`);
        return;
    }
    console.log(`Successfully running on port : ${port}`)
})