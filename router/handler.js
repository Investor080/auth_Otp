const express = require('express');
const router = express.Router();

const { signUp, verifyOtp, resendOtpVerificationCode, forgotPassword, resetPassword, login } = require('../controller/auth');

router.post("/signup", signUp);
router.post("/verify-otp", verifyOtp);
router.post("/resend-otp", resendOtpVerificationCode);
router.post("/login", login)
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);



module.exports = router