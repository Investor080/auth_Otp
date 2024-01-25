const mongoose = require('mongoose');
const {Schema, model} = mongoose
const userOtpVerificationSchema = new Schema({
    userId:{
        type: String,
    },
    otp:{
        type: String,
    },
    createdAt:{
        type: Date,
    },
    expiresAt:{
        type:Date
    }
});

const userOtpVerification = model("userOtpVerification", userOtpVerificationSchema)

module.exports = userOtpVerification