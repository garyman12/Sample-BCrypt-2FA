const express = require('express')
var bcrypt = require('bcrypt');
const Sequelize = require('sequelize');
const bodyparser = require('body-parser');
var flash = require('connect-flash');
var twoFactor = require('node-2fa');
var QRCode = require('qrcode');
const uuidv4 = require('uuid/v4'); // From UUIDV1 to V4 to improve security
const request = require("request");
var RateLimit = require('express-rate-limit');
const nodeCookie = require('node-cookie')
var time = require('time');
var saltRounds = 10;
const sequelize = new Sequelize('bcrypt', 'root', "", {
    host: 'localhost',
    dialect: 'mysql',
    operatorsAliases: false,
  
    pool: {
      max: 5,
      min: 0,
      acquire: 30000,
      idle: 10000
    },
    operatorsAliases: false
  });
  const User = sequelize.define('account', {
    username: {
      type: Sequelize.STRING
    },
    password: {
      type: Sequelize.STRING
    },
    secret: {
        type: Sequelize.STRING
    }
  });
  const api = sequelize.define('apikeys', {
    email: {
      type: Sequelize.STRING
    },
    name: {
      type: Sequelize.STRING
    },
    key: {
        type: Sequelize.STRING
    }
  });

  sequelize
  .authenticate()
  .then(() => {
    console.log('Connection has been established successfully.');
  })
  .catch(err => {
    console.error('Unable to connect to the database:', err);
  });
  sequelize.sync()
  var apiLimiter = new RateLimit({
    windowMs: 1*60*1000, 
    max: 10,
    delayMs: 0 ,
    message: "You've sent too many requests and are being throttled, please wait 60 seconds before sending anymore requests"
  });
const app = express()
var Cookiesecret = createRandomSecret(); // Using a random UUID to Sign and Encrypt Cookies to increase security of the user
var authCookieName = createRandomSecret(); // Using random UUID's for Auth cookies to increase security
console.log("Using: " + Cookiesecret + " for secure cookie generation.")
console.log("Using: " + authCookieName + "for Authentication Cookie Name.")
app.use(bodyparser.json())        
app.use(bodyparser.urlencoded({ extended: false }))
app.use('/api', apiLimiter);
app.enable('trust proxy')

app.get('/login', (req, res) => {
    res.sendFile(__dirname + "/Public/login.html");
});
app.get('/', (req,res) =>{
res.redirect("/login");
});
app.post('/login', (req, res) =>{
    comparePassword(req.body.username, req.body.password).then(function(result){
        User.find(({
            where:{
                username: req.body.username
            },
            attributes: [["secret", "secret"]]
        })).then(user => {
            if(user == null){
                res.redirect("/")
                reject("Non-Existent User Account entered")
            }else{
                parsed = user.get({
                    plain: true
                  });
                  console.log(req.body.facode)
                  console.log(parsed["secret"]);
                  console.log(twoFactor.verifyToken(parsed["secret"], req.body.facode));
                  if(twoFactor.verifyToken(parsed["secret"], req.body.facode) == null){
                      console.log("2FA Code Failed")
                      res.redirect("/")
                  }else{
                    createCookie(res, authCookieName , "Yes");
                    res.redirect("/testAuth");
                  }
                  

;
            }
        });
        console.log(twoFactor.verifyToken(result, req.body.facode));
    }).catch(function(result){
        console.log("Rejected Login for the following reason: " + result);
        res.redirect("/");
    })
});
app.get('/register', (req, res) => {
    res.sendFile(__dirname + "/Public/register.html");
    //TODO: Add in Auth function to check user cookie
});
app.get('/dashboard', function(req , res){
/* TODO:
    1. Add in Handlebar templates // IN PORGRESS
    2. Create Sequelize Function (Async or Promise based?!?!?) to pull data from the specific user account
    3. Add in cookie containing user email that will be used to pull data from the sequelize database // IN PROGRESS
*/

checkAuthorization(req, res).then(function(result){
    if(result == "Yes"){
        // Handle bars render template
    }else{
        res.send("Uh oh! An Error has happened, please try again later!"); // 
    }
}).catch(function(result){
    console.log("Authorization attempt requested! for ip: ")
    res.send("Your request has been denied! Please login to the application!");
})
    
});
app.post('/register', (req, res) =>{
createSecret(req.body.username, req.body.password).then(function(result){
    res.redirect(result["qr"]);
})



});

app.get('/registerapi', (req, res) =>{
    checkAuthorization(req, res).then(function(result){
        if(result == "Yes"){
            res.sendFile(__dirname + "/Public/createapi.html");
        }else{
            res.send("Uh oh! An Error has happened, please try again later!");
        }
    }).catch(function(result){
        console.log("Authorization attempt requested! for ip: ")
        res.send("Your request has been denied! Please login to the application!");
    })

});

app.post('/registerapi', (req, res) =>{

    checkAuthorization(req, res).then(function(result){
        if(result == "Yes"){
            createapi(req.body.email, req.body.name).then(function(result){
                res.send("Your API key is: " + result);
            });
        }else{
            res.send("Uh oh! An Error has happened, please try again later!");
        }
    }).catch(function(result){
        console.log("Authorization attempt requested! for ip: ")
        res.send("Your request has been denied! Please login to the application (and if you're using a post request, stop trying to break my stuff)");
    })

});

app.post('/api', (req, res) =>{
    apiAuthorization(req, res).then(function(result){
        if(result == false){
            res.status(401).send("Your request has been denied! Please check that you are using the proper AUTH header and API key")
        }else if (result == true){
            res.send("Welcome to my API endpoint! If you are getting this message, that means you have set up everything properly!")}
        }
    )
});
app.get('/testAuth', (req , res) =>{
checkAuthorization(req, res).then(function(result){
    if(result == "Yes"){
        res.send("Wooo it Worked!")
    }else{
        res.send("Uh oh! An Error has happened, please try again later!");
    }
}).catch(function(result){
    console.log("Authorization attempt requested! for ip: ")
    res.send("Your request has been denied! Please login to the application!");
})
});
app.post('/MeOw' , (req , res) => {
    apiAuthorization(req, res).then(function(result){
        if(result == false){
            res.status(401).send("Your request has been denied! Please check that you are using the proper AUTH header and API key")
        }else if (result == true){
            request('http://aws.random.cat/meow', function (error, response, body) {
            if(error){
                throw err
            }
        result = JSON.stringify({ URL: parsed["file"], Timestamp: time.Date() })
        res.send(result);
        console.log("API Call to MeOw from: " + req.ip)

        });
}
        }
    )
});

app.listen(3000, () => console.log('Example app listening on port 3000!'));

function createPassword(password){
    bcrypt.genSalt(saltRounds, function(err, salt) {
        bcrypt.hash(password, salt, function(err, hash) {
            return hash;
        });
    });
};
function createSecret(username, password){
    return new Promise(function(fulfill, reject){
        var newSecret = twoFactor.generateSecret({name: 'Adams Test Auth', account: username});
        createAccount(username , password, newSecret.secret);
        fulfill(newSecret)
    })
}

function check2facode(code, secret){
    twoFactor.verifyToken(secret, code)
}

function createCookie(res, cookieName , value){
    nodeCookie.create(res, cookieName, value,  {path: '/'}, Cookiesecret, true)
 
}
function getCookieValue(req, name){
    return new Promise(function(fulfill, reject){
        var value = nodeCookie.get(req, name, Cookiesecret, true)
        fulfill(value);
    })
}
function checkAuthorization(req, res){
    return new Promise(function(fulfill, reject){
    getCookieValue(req, authCookieName).then(function(result){
            if(result == "Yes"){
                fulfill("Yes");
            }else{
                reject("User is not logged in or tried faking an Authentication Cookie, Logging IP address.")

            }
                });


    });
}
function apiAuthorization(req, res){
    return new Promise(function(fulfill, reject){
        console.log(req.get("Authorization"));
        console.log(req.get("Email"));
        api.find(({
            where:{
                key: req.get("Authorization"),
                email: req.get("Email")
            }
        })).then(api => {
            if(api == null){
                fulfill(false);
            }else{
                parsed = api.get({
                    plain: true
                  });
                fulfill(true);
            }
    
        });
    });
}
function comparePassword(username, password, res){
    return new Promise(function(fulfill , reject){
        console.log(username)
        var parsed
        User.find(({
            where:{
                username: username
            },
            attributes: [["password", "password"]]
        })).then(user => {
            if(user == null){
                reject("Non-Existent User Account entered")
            }else{
                parsed = user.get({
                    plain: true
                  });
                  console.log(parsed["password"])
                bcrypt.compare(password, parsed["password"], function(err, res) {
                    console.log(res);
                    if(res == true){
                        console.log("Password and hash matched!")
                        fulfill("allowed");
                    }else{
                        console.log("Password and hash did not match!")
                        reject("Invalid password entered in (User Input did not match bcrypt hash)");
                    }
                });
            }
        })

    });
}
function createAccount(username, password, secret){
    bcrypt.hash(password, saltRounds).then(function(hash) {
        User.findOrCreate(({
            where:{
                username: username,
    
            },
            defaults:{
                username: username,
                password: hash,
                secret: secret
            }
        })).spread((user, created) => {
                
          });
    })
    


}

function createRandomSecret(){
    var secret = uuidv4();
    return secret
}
function createapi(email, name){
    return new Promise(function(fulfill, reject){
        var API = uuidv4();
        api.findOrCreate(({
            where:{
                email: email,
        
            },
            defaults:{
                email: email,
                name: name,
                key: API
            }
        })).spread((user, created) => {
            if(user == null){
                reject("Idk even know man");
            }else{
            fulfill(API)
            }
          });
            
    });
    


}
/*        User.find(({
            where:{
                username: username
            },
            attributes: [["secret", "secret"]]
        })).then(user => {
            if(user == null){
                res.redirect("/")
                reject("Non-Existent User Account entered")
            }else{
                parsed = user.get({
                    plain: true
                  });
                  console.log(parsed)
                  res.send("Success!");
;
            }
        }) */