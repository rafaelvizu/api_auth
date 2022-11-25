import express from 'express';
import cookieParser from 'cookie-parser';
import 'dotenv/config';

import Users from './models/User.mjs';
import db from './db.mjs'
import myM from './module/myModules.mjs';


const app = express();
const regEmail = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/;

app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));


app.post('/auth/register', async (req, res) => {
     const { username, email, password, confirmPassword } = req.body;
     if (req.cookies.token) {
          res.status(400).json({ message: 'You are already logged in' });

    } else if (!username || !email || !password || !confirmPassword) {
          return res.status(400).json({ message: "incorrect data" });

     } else if (
          password !== confirmPassword || 
          8 > password.length > 16 || 
          3 > username.length > 10 ||
          !regEmail.test(email)
     ) {
          return res.status(400).json({ message: "incorrect credentials"});

     } else if (await Users.findOne({email})) {
          return res.status(400).json({ message: "email already exists" });

     } else {
          await new Users({
               username,
               email,
               password: await myM.encryptPassword(password),
               hash: await myM.getHashData(username, email, password),
          }).save()
          .then((data) => {
               const token = myM.createToken(myM.getHashData(data.hash), process.env.MAX_AGE_SESSION);

               res.cookie('token', token, {maxAge: process.env.MAX_AGE_SESSION, httpOnly: true, sameSite: 'strict'});
               
               return token ? res.status(200).json({ message: "user created", token }):
                    res.status(500).json({ message: "server error" });
          })
          .catch(err => {
               console.error(err);
               return res.status(500).json({ message: "server error" });
          });

     }
});

app.post ('/auth/login', async (req, res) => {
     const { email, password } = req.body;

     if (!email || !password || 6 > password.length > 16 || !regEmail.test(email)) {
          return res.status(400).json({ message: "incorrect data" });

     } else if (req.cookies.token) {
          return res.status(400).json({ message: "already logged in" });

     } else {
          await Users.findOne({ email })
          .then(data => {
               if (data && myM.comparePassword(password, data.password)) {
                    const token = myM.createToken(myM.getHashData(data.hash), process.env.MAX_AGE_SESSION);

                    res.cookie('token', token, {maxAge: process.env.MAX_AGE_SESSION, httpOnly: true, sameSite: 'strict'});
                    
                    return token ? res.status(200).json({ message: "user logged in", token }):
                         res.status(500).json({ message: "server error" });

               } else {
                    return res.status(400).json({ message: "unregistered user" });
               }
          })
          .catch(err => {
               console.error(err);
               return res.status(500).json({ message: "server error" });
          });
     }
});

app.delete('/auth/logout', async (req, res) => {
     if (req.cookies.token) {
          res.clearCookie('token');
          return res.status(200).json({ message: "user logged out" });

     } else {
          return res.status(400).json({ message: "user not logged in" });
     }
});

async function checkToken(req, res, next) {
     const hash = myM.decoteMyToken(req.cookies.token);

     console.log(hash)
     // const data = await Users.findOne({hash})
     // .catch(err => {
     //      console.error(err);
     //      return res.status(500).json({ message: "server errord" });
     // });

     // if (data) {
     //      console.log(data);
     //      req.userHash = data;
     //      next();
     // } else {
     //      return res.status(400).json({ message: "unauthorized" });
     // }

     res.sendStatus(200);
}

app.get('/', checkToken, async () => {

});

const PORT = process.env.PORT || 3000;
if (db.status === 1) {
     app.listen(PORT, () => {
          console.log(`Server running on port ${PORT}`);
     });
} else {
     console.log("Error connecting to database");
}