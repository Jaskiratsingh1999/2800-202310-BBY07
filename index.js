
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

app.set('view engine', 'ejs');

const time = 1 * 60 * 60 * 1000; 

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = encodeURIComponent(process.env.MONGODB_PASSWORD);
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

app.get('/', (req, res) => {
  if (!req.session.authenticated) {
      res.render('index',  {authenticated: false} );
  }
  else {
      res.render('homePage', {authenticated: true, username: req.session.username, pictures: pictures});
  }
});

  app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

    res.send(`<h1>HELLO ${username}</h1>`);
});

app.get("/signUp", (req, res) => {
  res.render("signUp");
});

app.post('/signupSubmit', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;
    var dietaryPref = req.body.dietaryPreferences;

    if (!username || !email || !password) {
        let errorMsg =
          (!username ? "a username" :
          (!email ? "an email address" :
          "a password"));
        res.send(`Please provide ${errorMsg}. <br> <a href="/signup">Try again</a>`);
        return;
      }
    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ username, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render("errorMessage", { error: `${validationResult.error.message}`});
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
    
    await userCollection.insertOne({username: username, email: email, password: hashedPassword, dietary_preference: dietaryPref});
    req.session.authenticated = true; 
    req.session.email = email;  
    req.session.username = username;  
    console.log("Inserted user");
    res.redirect("/members");
});

app.get("/login", (req, res) => {
  res.render("login");
});
  

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render("errorMessage", { error: `${validationResult.error.message}`});
        return;
    }


    const result = await userCollection.find({email: email}).project({email: 1, password: 1, username: 1, user_type: 1, _id: 1}).toArray();


    console.log(result);
    if (result.length != 1) {
        console.log("Cannot find the user");
        res.render("errorMessage", { error: "We cannot find at the moment! "});
        return;
      }
      
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.email = email;
        req.session.username = result[0].username;
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = time;
        res.redirect('/members');
        return;
    }
    else {
        console.log("incorrect password");
        res.render("errorMessage", { error: "Your Password Incorrect!"});
        return;
    }
});


app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});


app.get('/members', (req, res) => {
  const email = req.session.email;
  const username = req.session.username;
  if (!req.session.authenticated) {
      res.redirect('/');
  }
  res.render("members", { username: username ,email: email});
});


app.get('/aboutUs', (req, res) => {
  res.render("aboutUs");
});

app.get('/favorites', (req, res) => {
  res.render("favorites");
});
app.get('/help', (req, res) => {
  res.render("help");
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.render("404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 

