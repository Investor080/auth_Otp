const express = require('express');
const { signUp, verifyOtp, resendOtpVerificationCode } = require('../controller/auth');


const router = express.Router();

router.route("/signup").post(signUp)
router.route("/verifyotp").post(verifyOtp)
router.route("/resendotpverificationcode").post(resendOtpVerificationCode)






module.exports = router