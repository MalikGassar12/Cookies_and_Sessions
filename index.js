import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";

const app = express();
const port = 3000;
const saltRounds = 10;

// Middlewares
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
// The session should always be before the passport
app.use(
  session({
    // The key word used to access the session
    //DO NOT PUT THIS KEY IN YOUR REPO AND UPLOAD IT TO GITHUB THIS IS JUST AN EXAMPLE
    secret: "TOPSECRET",
    // The session will expire after 30 minutes, if set to True you can save the session to database that way you can access it even if the server was updated or shut down
    resave: false,
    saveUninitialized: true,
    //the expiration time of the cookie in millieseconds
    cookie:{
      //This cookie will expire after a day
      maxAge: 1000 * 60 * 60 * 24,
    }
  })
);
// This has to be after starting a session
app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "5566gghhyy",
  port: 5432,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});
//make a new get for the authenticated users to return to without loggin in again
app.get("/secrets", (req, res) =>{
  
  // The IsAuthenticated property is a boolean value that indicates whether the current user is authenticated (logged in)
  if(req.isAuthenticated()){
    res.render("secrets.ejs");
  }else{
    res.redirect("login.ejs")
  }
})

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //hashing the password and saving it in the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          console.log("Hashed Password:", hash);
          //Using RETURNING * to save the user info in result
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0]; //saving the info user from result to user var
          // Use res.login NOT res.logIn
          //sending the user var that contains all user info into session with passport login
          res.login(user, (err) =>{
            console.log(err);
            res.redirect("/secrets")
          })
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});
//we will just pass passport as a middleware so that it can handle the login unlike what we do before which is using async function
app.post("/login", passport.authenticate("local", {
  // if it was successful you can redirect the user to secrets.ejs without loggin in again
  successRedirect: "/secrets",
  // if any failure redirect the user to the login page
  failureRedirect: "/login",
}));
// Not needed anymore cuz passport can access them without bodyparser
  // const email = req.body.username;
  // const loginPassword = req.body.password;

  


// A new object called local strategy that verifies if the username, password are right and calls a call back function (which is written as cb)
//A callback funciton is a function that is passed into another function to achive an action or a different route
passport.use(new Strategy(async function verify(username, password, cb){
  // Took the login proccess from the /login to put it in this strategy instead
  // passport has access to 'username, password' values form the register.ejs file wihtout the need to use bodyparser to get them as long as the names are matching
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      username,
    ]);
    if (result.rows.length > 0) {
      //returns id, username and password from database
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      // Compare is used to see if the hashed password in our database the same as the password enterd in the login field from the user
      bcrypt.compare(password, storedHashedPassword, (err, result) => {
        // if there is an error we will return it
        if (err) {
          return cb(err)
        } else {
          if (result) {
           // If the passwords match, we return the user object from the database
           return cb(null, user)
          } else {
            //This should not be err because there is nothing wrong with the server and this is a user error
            return cb(null, false)
          }
        }
      });
    } else {
      return cb("User Not Found")
    }
  } catch (err) {
    return cb(err);
  }
}));

// save the data if the user to a local storage
passport.serializeUser((user, cb) => {
  cb(null, user);
});
//DeserializerUser in a way so that you can handle/understand it
passport.deserializeUser((user, cb) => {
  cb(null, user);
})
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});


//Once done with the passport func you will now have cookies from the user and if you go to developer tools and check application you can see the collected cookies from the user in the browser