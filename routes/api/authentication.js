// Load Modules
const express = require("express");
const { check, validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("config");

// Create Router
const router = express.Router();

// Load Schema
const User = require("../../models/Users");

// Load Authentication Middleware
const authentication = require("../../middleware/authentication");

// Handling Get Request
router.get("/", authentication, async (req, res) => {
    try {
        const user = await User.findById(req.id).select("-password");
        res.json(user);
    } catch (error) {
        return res.status(500).json({
            errors: [{ msg: error.message }],
        });
    }
});

// Set Validations
const validate = [
    check("password", "Password Is Must Required").not().isEmpty(),
    check("password", "Password Must Be Greater Than Or Equal To 8").isLength({
        min: 8,
    }),
    check("email", "Email Is Must Required").not().isEmpty(),
    check("email", "Email Is Not In Valid Format").isEmail(),
];

// Handling Post Request
router.post("/", validate, async (req, res) => {
    let errors = validationResult(req);

    if (!errors.isEmpty()) {
        errors = errors.array().map((error) => ({
            msg: error.msg,
        }));
        return res.status(400).json({
            errors,
        });
    } else {
        let { email, password } = req.body;

        try {
            let user = await User.findOne({ email });

            if (!user) {
                return res.status(400).json({
                    errors: [{ msg: "User Is Not Registered" }],
                });
            } else {
                const isMatch = await bcrypt.compare(password, user.password);

                if (!isMatch) {
                    return res.status(401).json({
                        errors: [{ msg: "Invalid Credentials" }],
                    });
                } else {
                    const payload = {
                        id: user.id,
                    };

                    const jwtSecret = config.get("jwtSecret");

                    jwt.sign(
                        payload,
                        jwtSecret,
                        {
                            expiresIn: 3600,
                        },
                        (error, token) => {
                            if (error) throw error;
                            else return res.json({ token });
                        }
                    );
                }
            }
        } catch (error) {
            return res.status(500).json({
                errors: [{ msg: error.message }],
            });
        }
    }
});

// Export Module
module.exports = router;
