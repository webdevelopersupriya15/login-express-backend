const mongoose = require('mongoose');


const userSchema=new mongoose.Schema({
    name:String,
    email:String,
    password:String,
    thumbnail: String,
    phone:String,
    address:String,
    created_at:Date,
    updated_at:Date,
})

userSchema.pre('save', function(next) {
    const currentDate = new Date();
    
    if (this.isNew) { 
        this.created_at = currentDate;
    }
    next();
});

userSchema.pre('updateOne', function(next) {
    this.set({ updated_at: new Date() });
    next();
});

userSchema.pre('findByIdAndUpdate', function(next) {
    this.set({ updated_at: new Date() });
    next();
});


const User=mongoose.model('users',userSchema)

module.exports=User