const express = require('express')
var bcrypt = require('bcrypt');
const Sequelize = require('sequelize');
const bodyparser = require('body-parser');
var flash = require('connect-flash');
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

const app = express()
app.use(bodyparser.json())        
app.use(bodyparser.urlencoded({ extended: false }))


app.get('/', (req, res) => {
    res.sendFile(__dirname + "/Public/login.html");
});
app.post('/', (req, res) =>{
    comparePassword(req.body.username, req.body.password, res).then(function(result){
        // Create User Cookies
    }).catch(function(result){
        console.log("Rejected Login for the following reason: " + result);
    });
});
app.listen(3000, () => console.log('Example app listening on port 3000!'))

function createPassword(password){
    bcrypt.genSalt(saltRounds, function(err, salt) {
        bcrypt.hash(password, salt, function(err, hash) {
            return hash;
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
                res.redirect("/")
                reject("Non-Existent User Account entered")
            }else{
                parsed = user.get({
                    plain: true
                  });
                  console.log(parsed)
                bcrypt.compare(password, parsed["password"], function(err, res) {
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
function createAccount(username, password){
    bcrypt.hash(password, saltRounds).then(function(hash) {
        User.findOrCreate(({
            where:{
                username: username,
    
            },
            defaults:{
                username: username,
                password: hash
            }
        })).spread((user, created) => {
            console.log(
              user.get({
                plain: true
              })
            );

          });
    });
    


}

comparePassword("garyandtaz3212" , "testpassword123")