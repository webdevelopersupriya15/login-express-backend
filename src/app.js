const express=require('express');
const userRouter = require('./routes/website/user/userRoutes');


const webRoutes=express.Router()
const allRoutes=express.Router()

webRoutes.use('/user',userRouter)

allRoutes.use('/user-credential',webRoutes)

module.exports=allRoutes
