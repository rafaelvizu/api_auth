import db from '../db.mjs';


export default db.mongoose.model("User", new db.mongoose.Schema({
     username: String,
     email: String,
     password: String,
     hash: String,
}));

