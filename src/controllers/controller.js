
//website

const { userRegister, userLogin, viewUserData, updateUserData, genrateOtpToUpdate, updateUserPassword, verifyEmail, userLoginOtp, userEmailCheck, googleUserRegister, forgotPassword} = require("./website/userController");

module.exports={
    userRegister,
    userLogin,
    viewUserData,
    updateUserData,
    genrateOtpToUpdate,
    updateUserPassword,
    verifyEmail,
    userLoginOtp,
    userEmailCheck,
    googleUserRegister,
    forgotPassword
}