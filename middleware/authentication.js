// Load Module
const jwt = require("jsonwebtoken");
const config = require("config");

// Export Module
module.exports = (req, res, next) => {
    const token = req.header("x-auth-token");

    if (!token) {
        return res.status(401).json({
            errors: [{ msg: "No Token Found, Access Denied!" }],
        });
    } else {
        try {
            const { id } = jwt.verify(token, config.get("jwtSecret"));
            req.id = id;
            next();
        } catch (error) {
            return res.status(401).json({
                errors: [{ msg: error.message }],
            });
        }
    }
};
