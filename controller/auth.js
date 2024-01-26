require('dotenv').config();
const User = require('../models/user');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs')
const userOtpVerification = require('../models/userOtpVerification');


const signUp = async (req, res) => {
    const { username, email, password } = req.body
    if (!username) {
        return res.json({ error: "Username is required" })
    }
    if (!email) {
        return res.json({ error: "Email is required" })
    }
    if (!password) {
        return res.json({ error: "Password is required" })
    }
    if (!username || !email || !password) {
        return res.json({ error: "All fields are required" })
    }
    const existingUser = await User.findOne({ email })
    if (existingUser) {
        return res.status(400).json({ message: "User already exist" })
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const hashedOtp = await bcrypt.hash(otp, salt);
    const newUser = new User({
        username,
        email,
        password: hashedPassword,
        isVerified: false,
        otp: hashedOtp,
        otpExpires: Date.now() + 3600000,
    });

    newUser
        .save()
        .then((result) => {
            sendOtpVerificationEmail(result, res);
        })
        .catch((error) => {
            console.log(error)
            return res.status(500).json({ error: error.message })
        });


    const sendOtpVerificationEmail = async ({ _id, email }, res) => {
        try {
            const otp = `${Math.floor(1000 + Math.random() * 9000)}`;
            const transporter = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: process.env.my_email,
                    pass: process.env.pass
                },
            });
            const mailOptions = {
                from: process.env.email,
                to: email,
                subject: 'Verify Your Email',
                html: `<p>Enter <b>${otp}</b> in the app to verify your email address and complete the signup process <p><p>This code <b>expires in 1hour</b>.</p>`
            };
            transporter.sendMail(mailOptions, function (error, info) {
                if (error) {
                    console.log(error);
                };
            });
            res.json({
                status: "PENDING",
                message: "Verification otp email sent",
                data: {
                    userId: _id,
                    email,
                },
            });
        } catch (error) {
            console.log(error)
            return res.status(500).json({ error: error.message })
        }
    };
}


const verifyOtp = async (req, res) => {
    try {
        const { userId, otp } = req.body;
        if (!userId || !otp) {
            throw Error("Empty otp details are not allowed");
        } else {
            const existingUser = await User.findById(userId);
            if (!existingUser) {
                throw Error("User does not exist");
            }
            const validOtp = await bcrypt.compare(otp, existingUser.otp);
            if (!validOtp) {
                throw Error("Invalid OTP");
            }
            if (existingUser.otpExpires < Date.now()) {
                throw Error("OTP has expired");
            }
            existingUser.isVerified = true;
            await existingUser.save();
            res.status(200).json({ status: "SUCCESS", message: "OTP verified successfully" });
        }
    } catch (error) {
        console.log(error)
        res.status(500).json({ status: "FAILED", error: error.message });
    }
}

const resendOtpVerificationCode = async (req, res) => {
    try {
        const { userId, email } = req.body;
        if (!userId || !email) {
            throw Error("Empty user details are not allowed");
        } else {
            const existingUser = await User.findById(userId);
            if (!existingUser) {
                throw Error("User does not exist");
            }
            if (existingUser.isVerified) {
                throw Error("User already verified");
            }
            const otp = `${Math.floor(1000 + Math.random() * 9000)}`;
            const salt = await bcrypt.genSalt(10);
            const hashedOtp = await bcrypt.hash(otp, salt);
            existingUser.otp = hashedOtp;
            existingUser.otpExpires = Date.now() + 3600000;
            await existingUser.save();
            const transporter = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: process.env.my_email,
                    pass: process.env.pass
                },
            });
            const mailOptions = {
                from: process.env.email,
                to: email,
                subject: 'Verify Your Email',
                html: `<p>Enter <b>${otp}</b> in the app to verify your email address and complete the signup process <p><p>This code <b>expires in 1hour</b>.</p>`
            };
            transporter.sendMail(mailOptions, function (error, info) {
                if (error) {
                    console.log(error);
                };
            });
            res.status(200).json({ status: "SUCCESS", message: "Verification otp email sent" });
        }
    } catch (error) {
        res.status(500).json({ status: "FAILED", error: error.message })
    }
};

const login = async (req, res) => {
    const { email, password } = req.body
    try {
        const existingUser = User.findOne({ email })
        if (!existingUser) {
            return res.status(403).json({ message: "User Not Found" })
        }
        const passwordMatch = await bcrypt.compare(password, existingUser.password)
        if (!passwordMatch) {
            return res.status(403).json({ message: "Invalid Password" })
        }
    } catch {
        console.log(error)
        return res.status(500).json({ error: error.message })
    }
}

const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;
        const existingUser = User.findOne({ email: email })
        if (!existingUser) return res.status(403).json({ message: "You do not have an account with us" });
        const otp = `${Math.floor(1000 + Math.random() * 9000)}`;
        const salt = await bcrypt.genSalt(10);
        const hashedOtp = await bcrypt.hash(otp, salt);
        existingUser.passwordResetOtp = hashedOtp;
        existingUser.passwordResetOtpExpires = Date.now() + 3600000;
        existingUser.save();
        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.my_email,
                pass: process.env.pass
            },
        });
        const mailOptions = {
            from: process.env.email,
            to: email,
            subject: 'Password Reset',
            html: `<p>Enter <b>${otp}</b> in the app to reset your password <p><p>This code <b>expires in 1hour</b>.</p>`
        };
        transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                console.log(error);
            };
        });
    } catch (error) {
        console.log(error)
        return res.status(500).json({ error: error.message })
    }
}

const resetPassword = async (req, res) => {
    try {
        const { email, password, otp } = req.body;
        const existingUser = User.findOne({ email: email })
        if (!existingUser) return res.status(403).json({ message: "You do not have an account with us" });
        const validOtp = bcrypt.compare(otp, existingUser.passwordResetOtp);
        if (!validOtp) return res.status(403).json({ message: "Invalid OTP" });
        if (existingUser.passwordResetOtpExpires < Date.now()) return res.status(403).json({ message: "OTP has expired" });
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        existingUser.password = hashedPassword;
        existingUser.passwordResetOtp = undefined;
        existingUser.passwordResetOtpExpires = undefined;
        existingUser.save();
        res.status(200).json({ message: "Password Reset Successful" });
    } catch (error) {
        console.log(error)
        return res.status(500).json({ error: error.message })
    }
}





module.exports = {
    signUp,
    verifyOtp,
    resendOtpVerificationCode,
    forgotPassword,
    resetPassword
}