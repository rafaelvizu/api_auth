import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';


class myModules
{
     constructor()
     {
          this.bcrypt = bcrypt;
          this.jwt = jwt;
     }

     async encryptPassword(password) {
          return await this.bcrypt.hash(password, await this.bcrypt.genSalt(12));    
     } 

     async getHashData(...args) {
          args = args.toString().replace(',', '');
          return this.bcrypt.hash(args, await this.bcrypt.genSalt(10));
     }

     async comparePassword(password, hash) {
          return await this.bcrypt.compare(password, hash);
     }

     createToken(hash, expiresIn=86400) {
          try {
               return this.jwt.sign({ hash }, process.env.SECRET, { expiresIn });
          }
          catch (err) {
               console.error(err);
               return false;
          }
     }

     decoteMyToken(token) {
          try {
               jwt.verify(token, process.env.SECRET);   
               return jwt.decode(token);
          }
          catch (err) {
               return false;
          }
     }
}

export default new myModules();
