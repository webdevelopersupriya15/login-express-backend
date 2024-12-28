const express=require('express')
const { userRegister, userLogin, viewUserData, updateUserData, genrateOtpToUpdate, updateUserPassword, verifyEmail, userLoginOtp, userEmailCheck, googleUserRegister, forgetPassword, forgotPassword } = require('../../../controllers/controller')
const filesUploads = require('../../../middleware/multer,js')

const userRouter=express.Router()

userRouter.post('/user-register',userRegister)
userRouter.post('/user-login',userLogin)
userRouter.get('/user-viewdata/:id',viewUserData)
userRouter.put('/update-profile/:id',filesUploads('user'),updateUserData)
userRouter.post('/generate-otp', genrateOtpToUpdate)
userRouter.put('/update-password/:id',updateUserPassword)
userRouter.post('/verify-email', verifyEmail)
userRouter.post('/login-otp', userLoginOtp)
userRouter.post('/check-email',userEmailCheck)
userRouter.post('/google-user-register',googleUserRegister)
userRouter.put('/forgot-password',forgotPassword)

module.exports=userRouter

