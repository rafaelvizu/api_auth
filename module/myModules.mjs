import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';


class myModules
{
     constructor()
     {
          this.bcrypt = bcrypt;
     }

     async encryptPassword(password) {
          return await this.bcrypt.hash(password, await this.bcrypt.genSalt(12));    
     } 

     async getHashData(...args) {
          args = args.toString().replace(',', '');
          return await this.bcrypt.hash(args, await this.bcrypt.genSalt(15));
     }

     async comparePassword(password, hash) {
          return await bcrypt.compare(password, hash);
     }

     async createToken(hash, expiresIn=86400) {
          try {
               const SECRET = process.env.SECRET;
               console.log(hash)
               return jwt.sign({hash: `${hash}`}, SECRET, { expiresIn });
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
               console.error(err);
               return false;
          }
     }
}

export default new myModules();