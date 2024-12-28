const mongoose=require('mongoose');

const url=`mongodb+srv://${process.env.DB_USER_NAME}:${process.env.DB_PASSWORD}@cluster0.yjs98.mongodb.net/${process.env.DB_NAME}?retryWrites=true&w=majority&appName=Cluster0`;

mongoose.connect(url)
.then(()=>{
    console.log("Database connected")

})
.catch((error)=>{
    console.log(error)
})


