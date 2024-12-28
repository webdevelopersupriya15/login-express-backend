const express=require('express');
const allRoutes = require('./src/app')
require('dotenv').config()
require('./src/db/config')
const cors=require('cors')

const app=express()

app.use(express.json())
app.use(cors())
app.use('/user/user-profileimage/', express.static('src/uploads/user'));

app.use('/api',allRoutes)


app.listen(process.env.PORT,()=>{
    console.log(`Server is running on PORT ${process.env.PORT}`);
})