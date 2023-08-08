const router = require('express').Router()
const {register,login,user,forgotpassword, resetpassword, updateuser, updatepassword} = require('../controllers/auth')
const {protect,authorizeroles} = require('../middlewares/auth')

router.post('/register', register) // @searchkey   authregister
router.post('/login', login) // @searchkey   authlogin

router.get('/user',protect, user) // @searchkey   currentuser
router.put('/updateuser',protect, updateuser) // @searchkey   updateuser
router.put('/updatepassword',protect, updatepassword) // @searchkey   updatepassword

router.get('/forgotpassword', forgotpassword) // @searchkey   forgotpassword
router.put('/resetpassword/:resettoken', resetpassword) // @searchkey   resetpassword


// @desc this is a test route create to test "authorizeroles"
// This is a test route
router.get('/test',[protect,authorizeroles('admin')], (req, res) => {
    res.status(200).json({success: true})
})


module.exports = router
