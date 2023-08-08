const jwt = require('jsonwebtoken')
const User = require('../models/User')


const protect =  async(req, res, next) => {
    
    let token
    if(req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1]
    }
    
    // for cookie
    // else if(req.cookies.token) {
    //     token = req.cookies.token
    // }


    // make sure token exixts
    if(!token) {
        return res.status(401).json({success: false, msg: 'Not authorize to access this route'})  
    }
    try {
        const decoded  = jwt.verify(token, process.env.JWT_SECRET)
        // console.log(decoded)
        req.user = await User.findById(decoded.id)
        next()
    } catch (err) {
        console.log(err)
        return res.status(401).json({success: false, msg: 'Not authorize to access this route'})  
    }
}


// allow access to specific Roles
// @desc    in the middleware add the roles that are allowed to call the api
// @example | authorizeroles('user','guest') --> means user and guest is allowed to perform the action 
const authorizeroles = (...roles) => {
    return (req, res, next) => {
        if(!roles.includes(req.user.role)) {
            return res.status(403).json({success: false, msg: `user role '${req.user.role}' is Not authorize to access this route `})  
        }
        next()
    }
}


module.exports = {protect,authorizeroles}
