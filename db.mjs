import mongoose from "mongoose";
import 'dotenv/config.js';

class Conn
{
     constructor(BD_URL)
     {
          this.mongoose = mongoose;
          this.status = 0;
          this.BD_URL = BD_URL;
     }
     
     async connect()
     {
          await this.mongoose.connect(this.BD_URL)
          .then(() => {
               this.status = 1;
               console.log("Connected to database");
          })
          .catch(err => {
               console.error("Error connecting to database: ", err);
               this.status = 0; 
          })
     }

     async disconnect() {
          await this.mongoose.disconnect();
          console.log('Disconnected from database');
          this.status = 0;
     }

}

const db = new Conn(process.env.BD_URL);
await db.connect();

export default db;