const crypto = require('crypto')
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')


const UserSchema = new mongoose.Schema({
    name: {
      type: String,
      required: [true, 'Please add a name']
    },
    email: {
      type: String,
      required: [true, 'Please add an email'],
      unique: true,
      match: [
        /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
        'Please add a valid email'
      ]
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'guest'],
        default: 'user'
    },
    password: {
        type: String,
        required: [true, 'Please add a password'],
        minlength: 6,
        select: false
    },
    resetPasswordToken: String,
    resetPasswordExpire: Date,
    createdAt: {
        type: Date,
        default: Date.now
    }
})

// Encrypt password before save
UserSchema.pre('save', async function(next) {
    if(!this.isModified('password')) {
      next()
    }
    const salt = await bcrypt.genSalt(10)
    this.password = await bcrypt.hash(this.password, salt)
})

// geenrate password reset token and assigen it to the db.
UserSchema.methods.getResetPasswordToken = function() {
    //Generate Token
    const resetToekn = crypto.randomBytes(20).toString('hex')
  
    //hash token and set to reset ResetpassowrdToken
    this.resetPasswordToken = crypto
                                .createHash('sha256')
                                .update(resetToekn)
                                .digest('hex')
    
    // set expire
    this.resetPasswordExpire = Date.now() + 10 * 60 * 1000
  
    return resetToekn
}


module.exports = mongoose.model('user', UserSchema)