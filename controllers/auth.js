const User = require('../models/User')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const SendMail = require('../utils/SendMail')
const crypto = require('crypto')

// @searchkey   authregister
// @desc    Register user
// @info    Public | POST /api/v1/auth/register
const register = async(req, res, next) => {
    try {
        const { name, email, password, role } = req.body
        if(!name || !email || !password || !role){
            return res.status(400).json({ msg: 'please enter the required feilds' })
        }

        const user = await User.create({
            name, email,password,role
        })

        // creating jwt token
        const token = await jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: process.env.JWT_EXPIRE})
        
        // creating auth cookie
        const options = {
            expires: new Date(Date.now() + (process.env.JWT_COOKIE_EXPIRE*24*60*1000)),
            httpOnly: true
        }
        if(process.env.NODE_ENV === 'production') {
            options.secure = true
        }

        // sending respose
        res.status(200).cookie('token', token, options).json({success: true, token})
    } catch (err) {
        console.log(err)
        res.status(400).json({success: false, error: err.message})
    }
}
// @searchkey   authlogin
// @desc    login user
// @info    Public | POST POST /api/v1/auth/login
const login = async(req, res, next) => {
    try {
        const { email, password } = req.body
        if(!email || !password ){
            return res.status(400).json({ msg: 'please enter the required feilds' })
        }

        // checking if the user exists
        const user = await User.findOne({ email: email }).select('+password')
        if(!user) {
            return res.status(401).json({success: false, message: 'invalid credentials'})
        }

        // checking if the password matchs
        const isMatch = await bcrypt.compare(password, user.password)
        if(!isMatch ) return res.status(401).json({ msg: 'invalid credentials' })

        // creating jwt token
        const token = await jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: process.env.JWT_EXPIRE})
        
        // creating auth cookie
        const options = {
            expires: new Date(Date.now() + (process.env.JWT_COOKIE_EXPIRE*24*60*1000)),
            httpOnly: true
        }
        if(process.env.NODE_ENV === 'production') {
            options.secure = true
        }
        
        // sending respose
        res.status(200).cookie('token', token, options).json({success: true, token})
        
    } catch (err) {
        console.log(err)
        res.status(400).json({success: false, error: err.message})
    }
}

// @searchkey   currentuser
// @desc    Current logged in user
// @info    Private | POST /api/v1/auth/user
const user = async (req, res, next)=> {
    try {
        const user = await User.findById(req.user.id)

        res.status(200).json({
            success: true,
            data: user
        })
    } catch (err) {
        console.log(err)
        return res.status(401).json({success: false, msg: 'Not authorize to access this route'})  
    }
}

// @searchkey   updateuser
// @desc    update user details
// @info    Private | PUT /api/v1/auth/updateuser
const updateuser = async (req, res, next)=> {
    try {
        const {email, name, role} = req.body
        const user = await User.findByIdAndUpdate(req.user.id, {
            email, name,role
        }, {
            new: true,
            runValidators: true
        })
        res.status(200).json({
            success: true,
            data: user
        })
    } catch (err) {
        console.log(err)
        return res.status(401).json({success: false, msg: 'Not authorize to access this route'})  
    }
}

// @searchkey   updatepassword
// @desc    Update password
// @info    Private | PUT /api/v1/auth/updatepassword
const updatepassword = async (req, res, next)=> {
    try {
        const user = await User.findById(req.user.id).select('+password')

        // currunt password
        const isMatch = await bcrypt.compare(req.body.curruntpassword, user.password)

        if(!isMatch) {
            return res.status(401).json({success: false, msg: 'Password is incorrect'})  
        }

        user.password = req.body.password
        await user.save()

        res.status(200).json({
            success: true,
            data: 'password changed, Please login back to the platfrom'
        })
    } catch (err) {
        console.log(err)
        return res.status(401).json({success: false, msg: 'Not authorize to access this route'})  
    }
}


// @searchkey   forgotpassword
// @desc    Forgot Password
// @info    Public | POST /api/v1/auth/forgotpassword
const forgotpassword = async (req, res, next)=> {
    try {
        const user = await User.findOne({email: req.body.email})
        
        if(!user){
            return res.status(404).json({success: false, msg: 'User doesnt exist'})  
        }
        
        //Get reset token
        const resetToken = user.getResetPasswordToken()
        await user.save({ validateBeforeSave: false })
        
        const resetUrl = `${req.protocol}://${req.get('host')}/api/v1/auth/resetpassword/${resetToken}`
        const message = `You are receving this email because you are tryig to change your password. 
                        please use the following link to change your password: \n\n ${resetUrl}`
    

        const sentmail = await SendMail({
            email: user.email,
            subject: 'password reset token',
            message: message
        })
        
        res.status(200).json({
            success: true,
            data: 'Email sent'
        })
    } catch (err) {
        console.log(err)
        user.resetPasswordToken = undefined
        user.resetPasswordExpire = undefined

        await user.save({ validateBeforeSave: false })

        return res.status(500).json({success: false, msg: 'email cant be send'})  
    }
}

// @searchkey   resetpassword
// @desc    reset password
// @info    Public | PUT /api/v1/auth/resetpassword
const resetpassword = async (req, res, next)=> {
    try {
        const resetPasswordToken = crypto
        .createHash('sha256')
        .update(req.params.resettoken)
        .digest('hex')

        const user = await User.findOne({
                resetPasswordToken,
                resetPasswordExpire: { $gt: Date.now() }
        })

        if(!user) {
            return res.status(400).json({success: false, msg: 'Invalid Token'})  
        }

        // changing the password
        user.password = req.body.password
        user.resetPasswordToken = undefined
        user.resetPasswordExpire = undefined
        await user.save({ validateBeforeSave: false })

        res.status(200).json({
            success: true,
            data: 'password reset success.'
        })
    } catch (err) {
        console.log(err)

        return res.status(500).json({success: false, msg: 'Error from Server, cant reset the password'})  
    }
}




module.exports = {register, login, user, forgotpassword, resetpassword, updateuser, updatepassword}