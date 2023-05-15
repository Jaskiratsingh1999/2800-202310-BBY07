
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const nodemailer = require('nodemailer');

const clientId = process.env.CLIENT_ID;
const clientSecret = process.env.CLIENT_SECRET;
const refreshToken = process.env.REFRESH_TOKEN;
const accessToken = process.env.ACCESS_TOKEN;

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    type: 'OAuth2',
    user: 'meal.geniebby07@gmail.com',
    clientId: clientId,
    clientSecret: clientSecret,
    refreshToken: refreshToken,
    accessToken: accessToken
  },
});


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
    res.render('index', { authenticated: false });
  }
  else {
      res.redirect('/members');
  }
});

app.get('/favorites', (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/');
  } else {
    res.render('favorites', {authenticated: true, username: req.session.username});
  }
});


  app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

  if (!username) {
    res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(40).required();
  const validationResult = schema.validate(username);

  // A URL parameter of user[$ne]=name would get executed as a MongoDB command
  // and may result in revealing information about all users or a successful
  // login without knowing the correct password.
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
    return;
  }

  const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

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
      username: Joi.string().alphanum().max(40).required(),
      email: Joi.string().email().required(),
      password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ username, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render("404", { error: `${validationResult.error.message}`});
        return;
    }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({ username: username, email: email, password: hashedPassword, dietary_preference: dietaryPref, resetToken: "" });
  req.session.authenticated = true;
  req.session.email = email;
  req.session.username = username;
  console.log("Inserted user");
  res.redirect("/members");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get('/search', (req, res) => {
  res.render("search");
});
/* Section handling code for forgotten password  */
//////////////////////////////////////////////////
const { google } = require('googleapis');

async function updateUserResetToken(email, resetToken) {
  await userCollection.updateOne({ email: email }, { $set: { resetToken: resetToken } });
}

const crypto = require('crypto');

function generateResetToken() {
  return crypto.randomBytes(20).toString('hex');
}

app.get('/forgot-password', async (req, res) => {
  const { email } = req.query;

  // Generate a unique reset token
  const resetToken = generateResetToken();

  // Store the reset token in the user's document
  await updateUserResetToken(email, resetToken);

  // Send the password reset email with the reset token
  const resetLink = `http://${req.get('host')}/password-reset?token=${resetToken}&email=${email}`;
  const mailOptions = {
    from: 'meal.geniebby07@gmail.com',
    to: email,
    subject: 'Password Reset',
    text: `Please click the following link to reset your password: ${resetLink}`
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Password reset email sent successfully');
  } catch (error) {
    console.error('Error sending password reset email:', error);
    // Handle the error appropriately
  }

  // Redirect the user to a password reset confirmation page
  res.redirect('/password-reset-confirmation');
});

app.get('/password-reset-confirmation', (req, res) => {
  res.render('password-reset-confirmation');
});

app.post('/reset-password', async (req, res) => {
  const { resetToken, newPassword } = req.body;

  try {
    const user = await userCollection.findOne({ resetToken });

    if (!user) {
      return res.status(400).send('Invalid or expired reset token.');
    }

    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    await userCollection.updateOne({ _id: user._id }, { $set: { password: hashedPassword, resetToken: '' } });

    // Password updated successfully, redirect to password reset success page
    return res.redirect('/password-reset-success');
  } catch (error) {
    console.error('Error updating password:', error);
    // Handle the error appropriately
    return res.status(500).send('An error occurred while updating the password.');
  }
});


app.get('/password-reset', (req, res) => {
  const resetToken = req.query.token;
  const email = req.query.email;
  res.render('password-reset', { resetToken, email });
});

app.get('/password-reset-success', (req, res) => {
  res.render('password-reset-success');
});



// app.get('/oauth2callback', async (req, res) => {
//   const oauth2Client = new google.auth.OAuth2(
//     '910604869949-4cdlptmrhs1c9jb5c6h2rqf30k5gfvbd.apps.googleusercontent.com',
//     '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',
//     'https://localhost:3000/oauth2callback'
//   );
app.get('/oauth2callback', async (req, res) => {
  const oauth2Client = new google.auth.OAuth2(
    '910604869949-4cdlptmrhs1c9jb5c6h2rqf30k5gfvbd.apps.googleusercontent.com',
    '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',
    'http://localhost:3000/oauth2callback'  // <-- Make sure this matches the URI you set in Google Cloud Console
  );

  const { code } = req.query;

  if (code) {
    try {
      const { tokens } = await oauth2Client.getToken(code);
      oauth2Client.setCredentials(tokens);

      // Now the oauth2Client is authorized and you can use it to make requests
      // You could also save the tokens for later use

      res.send('Successfully authenticated');
    } catch (error) {
      res.send('Error retrieving access token');
    }
  } else {
    res.send('No authorization code found');
  }
});


//////////////////////////////////////////////////////
/* Section handling code for forgotten password END */

app.post('/loggingin', async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().max(40).required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.render("errorMessage", { error: `${validationResult.error.message}` });
    return;
  }


  const result = await userCollection.find({ email: email }).project({ email: 1, password: 1, username: 1, user_type: 1, _id: 1 }).toArray();


    console.log(result);
    if (result.length != 1) {
        console.log("Cannot find the user");
        res.render("404", { error: "We cannot find at the moment! "});
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
        res.render("404", { error: "Your Password Incorrect!"});
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
  res.render("members", { username: username, email: email });
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

app.get('/faq', (req, res) => {
  res.render("faq");
});

app.get('/profile', async (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/');
  } else {
    try {
      const result = await userCollection.find({email: req.session.email}).project({email: 1, password: 1, username: 1, dietary_preference: 1, image: 1 ,id: 1}).toArray();
      const user = result[0];
      console.log(user.image);
      res.render('profile', { user});
    } catch (err) {
      console.error('Failed to fetch user', err);
      res.status(500).send('Internal Server Error');
    }
  }
});

const MIN_PASSWORD_LENGTH = 4; // define minimum password length constant

app.post('/profile/password', async (req, res) => {
  const { password } = req.body;
  if (password.length < MIN_PASSWORD_LENGTH) {
    return res.status(400).send(`Password must be at least ${MIN_PASSWORD_LENGTH} characters long`);
  }
  else{
  const hashedPassword = await bcrypt.hash(password, 12);
  console.log(hashedPassword);
  const result = await userCollection.updateOne({ email: req.session.email }, { $set: { password: hashedPassword } });
  if (result.modifiedCount === 1) {
    console.log('Password updated successfully');
    res.redirect('/profile');
  } else {
    res.send('Failed to update password');
  }
}
});

const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { Console } = require("console");

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/uploads'); // set the destination folder for uploaded images
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9); // add a unique suffix to the filename to avoid overwriting existing files
    const ext = path.extname(file.originalname);
    cb(null, `${req.session.username}_${uniqueSuffix}${ext}`); // use the user ID to generate a unique filename
  },
});

const upload = multer({ storage: storage });

app.post('/profile/image', upload.single('profileImage'), async (req, res) => {
  if (!req.file) {
    return res.status(400).send('No file uploaded');
  }

  const imageUrl = `uploads/${req.file.filename}`; // the URL to store in the database
  try {
    // update the user's image URL in the database
    const result = await userCollection.updateOne({ email: req.session.email }, { $set: { image: imageUrl } });
    if (result.modifiedCount === 1) {
      console.log('Image updated successfully');
      res.redirect('/profile');
    } else {
      res.send('Failed to update image');
    }
  } catch (error) {
    console.log('Error updating image:', error);
    res.send('Failed to update image');
  }
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.render("404");
})

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});

