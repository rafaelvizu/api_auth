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
          const passwordHash = await myM.encryptPassword(password);
          await new Users({
               username,
               email,
               password: passwordHash,
               hash: await myM.getHashData(username, passwordHash, Math.random() * 1000),
          }).save()
          .then(async (data) => {
               const token = myM.createToken(data.hash, process.env.MAX_AGE_SESSION);

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
          .then(async  data => {
               if (data && await myM.comparePassword(password, data.password)) {
                    const token = myM.createToken(data.hash, process.env.MAX_AGE_SESSION);

                    res.cookie('token', token, {maxAge: process.env.MAX_AGE_SESSION, httpOnly: true, sameSite: 'strict'});
                    
                    return token ? res.status(200).json({ message: "user logged in", token }):
                         res.status(500).json({ message: "server error" });

               } else {
                    return res.status(400).json({ message: "incorrect data" });
               }
          })
          .catch(err => {
               console.error(err);
               return res.status(500).json({ message: "server error" });
          });
     }
});

app.post('/auth/newpassword', checkToken, async (req, res) => {
     const { password, newPassword, confirmPassword } = req.body;

     if (!password || !newPassword || !confirmPassword || 8 > newPassword.length > 16 || newPassword !== confirmPassword) {
          return res.status(400).json({ message: "incorrect data" });

     } else if (password === newPassword) {
          return res.status(400).json({ message: "same passwords" });

     } else {
          await Users.findById(req.userData._id)
          .then(async data => {
               if (await myM.comparePassword(password, data.password)) {
                    const passwordHash = await myM.encryptPassword(newPassword);
                    const hash = await myM.getHashData(req.userData.username, passwordHash, Math.random() * 1000);

                    await Users.findByIdAndUpdate({_id: data.id}, {password: passwordHash, hash})
                    .then(() => { 
                         const token = myM.createToken(hash, process.env.MAX_AGE_SESSION);
                         res.cookie('token', token, {maxAge: process.env.MAX_AGE_SESSION, httpOnly: true, sameSite: 'strict'});
                         return res.status(200).json({ message: "password changed" });
                    })
                    .catch(err => {
                         console.error(err);
                         return res.status(500).json({ message: "server error" });
                    });

               } else return res.status(400).json({ message: "incorrect data" });

          })
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

     if (!req.cookies.token) return res.status(400).json({'message': 'user not logged in'});

     const tokenData = myM.decoteMyToken(req.cookies.token);
     if (!tokenData) return res.status(500).json({'message': 'token error'});

     const data = await Users.findOne({hash: tokenData.hash}, '-password -hash -__v')
     .catch(err => {
          console.error(err);
          return res.status(500).json({ message: "server error" });
     });

     if (data) {
          req.userData = data;
          next();
     } else {
          return res.status(400).json({ message: "unauthorized" });
     }
}

app.get('/', checkToken, (req, res) => {
     return res.status(200).json(req.userData);
});

const PORT = process.env.PORT || 3000;
if (db.status === 1) {
     app.listen(PORT, () => {
          console.log(`Server running on port ${PORT}`);
     });
} else {
     console.log("Error connecting to database");
}