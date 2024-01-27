require('dotenv').config();
require('dotenv').config();
const User = require('../models/user');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

passport.use('signup', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
},
    async (req, email, password, done) => {
        try {
            // Check if user with the same email exist
            const user = await User.findOne({ email });
            if (user) {
                return done(null, false, { message: 'User already exist' });
            }

            // Hash the password using bcrypt
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            // Create a new user
            const newUser = new User({
                username: req.body.username,
                email: email,
                password: hashedPassword,
                isVerified: false,
                otp: hashedPassword,
                otpExpires: Date.now() + 3600000,
            });

            await newUser.save();

            // Create a token
            const token = jwt.sign({ _id: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

            return done(null, { newUser, token });
        } catch (error) {
            return done(error);
        }
    })
);

const signUp = async (req, res, next) => {
    passport.authenticate('signup', (err, data, info) => {
        if (err) {
            console.log(err);
        }
        if (info != undefined) {
            console.log(info.message);
            res.status(403).send(info.message);
        } else {
            sendOtpVerificationEmail(data.newUser, res);
            res.status(200).send(data);
        }
    })(req, res, next);
};

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
    const { identifier, password } = req.body;
    try {
        const existingUser = await User.findOne({ $or: [{username: identifier}, {email: identifier}], });
        if (!existingUser) {
            return res.json({ error: "User not found. Please signup to continue" });
        }
        const passwordMatch = await bcrypt.compare(password, existingUser.password);
        if (!passwordMatch) {
            return res.json({ error: "Invalid Credentials" });
        }

        req.login(existingUser, { session: false }, (err) => {
            if (err) {
                return res.json(err);
            }

            passport.authenticate("local", { session: false }, (err, user, info) => {
                if (err || !user) {
                    return res.status(400).json({
                        message: 'Something is not right',
                        user: user
                    });
                }


                const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
                return res.json({ user: { email: user.email, username: user.username }, token });
            })(req, res);
        });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ error: error.message });
    }
};

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
    login,
    forgotPassword,
    resetPassword
}