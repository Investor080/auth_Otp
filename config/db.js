require('dotenv').config();
const mongoose = require('mongoose');
ConnectionString = process.env.Connection_String

const connectDb = async () =>{
    await mongoose.connect (ConnectionString)
    console.log("DB is connected");
}

module.exports = connectDb