require('./bootstrap') // Setup error handlers
require('songbird')

let bodyParser = require('body-parser')
let cookieParser = require('cookie-parser')
let session = require('express-session')
let passport = require('passport')
let express = require('express')
let morgan = require('morgan')
let LocalStrategy = require('passport-local').Strategy
let wrap = require('nodeifyit')
let flash = require('connect-flash')
let crypto = require('crypto')
let SALT = 'CodePathHeartNodeJS'
let mongoose = require('mongoose')
let User = require('./user.js')

const NODE_ENV = process.env.NODE_ENV
const PORT = process.env.PORT || 8000

let app = express()
app.set('view engine', 'ejs')
app.use(flash())
app.use(cookieParser('ilovethenodejs')) // Session cookies
app.use(bodyParser.json()) // req.body for PUT/POST requests (login/signup)
app.use(bodyParser.urlencoded({ extended: true }))

// In-memory session support, required by passport.session()
app.use(session({
  secret: 'ilovethenodejs',
  resave: true,
  saveUninitialized: true
}))

app.use(passport.initialize()) // Enables passport middleware
app.use(passport.session()) // Enables passport persistent sessions

var user = {
    email: 'foo@foo.com',
//     password: 'asdf'
	password: crypto.pbkdf2Sync('asdf', SALT, 4096, 512, 'sha256').toString('hex')
}

// passport.use(new LocalStrategy({
//     usernameField: 'email', // Use "email" field instead of "username"
// }, wrap(async (email, password) => {
//     email = (email || '').toLowerCase()
//     if (email !== user.email) {
//         return [false, {message: 'Invalid username'}]
//     }
//     if (password !== user.password) {
//         return [false, {message: 'Invalid password'}]
//     }
//     return user
// }, {spread: true})))

passport.use(new LocalStrategy({
    usernameField: 'email',
    failureFlash: true // Enables error messaging
}, wrap(async (email, password) => {
   if (email !== user.email) {
       return [false, {message: 'Invalid username'}]
   }

    let passwordHash = await crypto.promise.pbkdf2(password, SALT, 4096, 512, 'sha256')
   if (passwordHash.toString('hex') !== user.password) {
       return [false, {message: 'Invalid password'}]
   }
   return user
}, {spread: true})))

mongoose.connect('mongodb://127.0.0.1:27017/authenticator')

passport.use('local-signup', new LocalStrategy({
   usernameField: 'email'
}, wrap(async (email, password) => {
    email = (email || '').toLowerCase()

    if (await User.promise.findOne({email})) {
        return [false, {message: 'That email is already taken.'}]
    }

    user = new User()
    user.email = email

    // Store password as a hash instead of plain-text
    user.password = (await crypto.promise.pbkdf2(password, SALT, 4096, 512, 'sha256')).toString('hex')
    return await user.save()
}, {spread: true})))

// passport.use('local-login', new LocalStrategy({
//    usernameField: 'email'
// }, wrap(async (email, password) => {
//     email = (email || '').toLowerCase()
// 
//     if (await User.promise.findOne({email})) {
//         return [false, {message: 'That email is already taken.'}]
//     }
// 
//     let user = new User()
//     user.email = email
// 
//     // Store password as a hash instead of plain-text
//     user.password = (await crypto.promise.pbkdf2(password, SALT, 4096, 512, 'sha256')).toString('hex')
//     return await user.save()
// }, {spread: true})))

passport.use('local-login', new LocalStrategy({
    usernameField: 'email',
    failureFlash: true // Enables error messaging
}, wrap(async (email, password) => {
	user = await User.findOne({email}).exec()
 	if (email !== user.email) {
     return [false, {message: 'Invalid username'}]
 	}

  let passwordHash = await crypto.promise.pbkdf2(password, SALT, 4096, 512, 'sha256')
 	if (passwordHash.toString('hex') !== user.password) {
     return [false, {message: 'Invalid password'}]
 	}
 	return user
}, {spread: true})))


passport.serializeUser(wrap(async (user) => user.email))
// passport.deserializeUser(wrap(async (email) => user))
passport.deserializeUser(wrap(async (email) => {
    return await User.findOne({email}).exec()
}))

// start server 
app.listen(PORT, ()=> console.log(`Listening @ http://127.0.0.1:${PORT}`))

// app.get('/', (req, res) => res.render('index.ejs', {}))
app.get('/', (req, res) => {
    res.render('index.ejs', {message: req.flash('error')})
})

// app.post('/login', passport.authenticate('local', {
//     successRedirect: '/profile',
//     failureRedirect: '/',
//     failureFlash: true
// }))

app.post('/login', passport.authenticate('local-login', {
    successRedirect: '/profile',
    failureRedirect: '/',
    failureFlash: true
}))

app.post('/signup', passport.authenticate('local-signup', {
    successRedirect: '/profile',
    failureRedirect: '/',
    failureFlash: true
}))

function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) return next()
    res.redirect('/')
}

// app.get('/profile', isLoggedIn, (req, res) => res.render('profile.ejs', {}))

app.get('/profile', isLoggedIn, (req, res) => {
	res.render('profile.ejs', {id: user._id, email: user.email, password: user.password})
})

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

