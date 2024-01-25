const express = require('express');
const passport = require('passport');
const connectDB = require ('./config/db')
const app = express();
require('dotenv').config();
const router = require ('./router/handler')
const port = process.env.PORT || 3000;

//Middlewares

app.use(express.json())

app.use(passport.initialize())

app.use ('/api/v1', router)


app.listen (port, () =>{
    connectDB()
    console.log(`Server started on port ${port}`);
})