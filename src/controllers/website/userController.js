const axios  = require('axios');
const User = require('../../models/user');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const saltRounds = 10;
const otpStore = new Map();

const SECRET_KEY=process.env.SECRET_KEY

const userRegister=async(req,res)=>{
    try{
        //console.log(req.body)
        const {name,email,password}=req.body;
        const userExist=await User.findOne({email});

        if(userExist) return res.status(403).json({message:'Email Id already Exist'})

        bcrypt.hash(password, saltRounds, async (error, hashedPassword) => {
                console.log(hashedPassword);
                const dataToSave = new User({
                    name,
                    email,
                    password:hashedPassword
                });
                const response = await dataToSave.save();
        
                res.status(200).json({message:'success',data: response })
        }) 
     
    }
    catch(error){
        console.log(error);
        res.status(500).json({message:'Internal Server error'})
    }
}

const userLogin=async(req,res)=>{
    try{
        //console.log(req.body)
        
        const userExist=await User.findOne({email: req.body.email }); // findOne-it returns an object
        
        if(!userExist) return res.status(403).json({message:'Email Id does not exist'})

        const isMatch = await bcrypt.compare(req.body.password, userExist.password);

        if (!isMatch) return res.status(401).json({ message: 'Please provide a valid password' });
        
        const recaptchaValue=req.body.recaptchaValue
       
    

        const recaptchaResponse = await axios.post(`https://www.google.com/recaptcha/api/siteverify?secret=${SECRET_KEY}&response=${recaptchaValue}`);

    

        // const recaptchaResponse = await axios.post('https://www.google.com/recaptcha/api/siteverify',null,{
        //     params: {
        //         secret: SECRET_KEY, // Your reCAPTCHA secret key
        //         response: recaptchaValue, // Token from the client
        //     },
        // });

        if (!recaptchaResponse.data.success) {
            return res.status(400).json({ message: 'reCAPTCHA verification failed. Please try again.' });
        }
        const filePath = `${req.protocol}://${req.get('host')}/user/user-profileimage/`;

        jwt.sign(userExist._doc, process.env.JWT_KEY, { expiresIn: 60 * 60 * 24 * 7 }, (error, token) => {
            console.log(error)
            if (error) return res.status(500).json({ message: 'something went wrong' });
            res.status(200).json({ message: 'success', data: userExist, auth: token,path:filePath });
        })
        
    }
    catch(error){
        console.log(error);
        res.status(500).json({message:'Internal Server error'})
    }
}

const viewUserData=async(req,res)=>{
    try{
        console.log(req.params)
        const userExist=await User.findOne({_id:req.params.id});
        console.log(userExist)
        const filePath = `${req.protocol}://${req.get('host')}/user/user-profileimage/`;

        res.status(200).json({ message: 'success',data:userExist,file_path: filePath });
    }
    catch(error){
        console.log(error);
        res.status(500).json({message:'Internal Server error'})
    }

}
const updateUserData=async(req,res)=>{
    try{
        const data = req.body;

        const userExist = await User.findById(req.params.id);
        
        if (!userExist) {
            return res.status(404).send('User not found');
        }

        if (req.files && req.files.thumbnail && req.files.thumbnail.length > 0) {
            console.log(req.files);
            
            // Fetch the new file details
            const newThumbnail = req.files.thumbnail[0];
            const filename = newThumbnail.filename;
            const fileExtension = path.extname(filename);
            const fileSize = newThumbnail.size;

            // Validate the uploaded thumbnail format
            if (fileExtension !== '.jpeg' && fileExtension !== '.jpg') {
                // Only delete the newly uploaded file, not the old one
                fs.unlinkSync(path.join(__dirname, `../../uploads/user/${filename}`)); 
                return res.status(422).json({ message: 'Invalid file type' });
            }

            // Validate the uploaded thumbnail size
            if (fileSize > 2 * 1024 * 1024) { // 2MB in bytes
                fs.unlinkSync(path.join(__dirname, `../../uploads/user/${filename}`));
                return res.status(413).json({ message: 'File Size should be 2MB' });
            }

            // If validation passes, delete the old thumbnail if it exists
            if (userExist.thumbnail) {
                fs.unlinkSync(path.join(__dirname, `../../uploads/user/${userExist.thumbnail}`));
            }

            // Assign the new thumbnail filename to data
            data.thumbnail = filename;
        }
       
    
        const response = await User.findByIdAndUpdate(
            {_id:req.params.id},
            { $set: data },
            { new: true, runValidators: true } // Options: returns the updated document, validates before updating
        );
        if (!response) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.status(200).json({message: 'success',data:response});
    }
    catch(error){
        console.log(error);
        res.status(500).json({message:'Internal Server error'})
    }
}
const genrateOtpToUpdate = async(req, res)=>{
    try{
       
        console.log(req.body);
        const generatedOtp = Math.floor(Math.random() * 9000) + 1000;
        console.log(generatedOtp)

        otpStore.set(req.body.email, generatedOtp);

        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.DOMAIN_EMAIL,
                pass: process.env.APP_PASSWROD
            }
        });

        const mailOption = {
            from: process.env.DOMAIN_EMAIL,
            to: req.body.email,
            subject: 'OTP for update email',
            text: `Your OTP is ${generatedOtp}`
        };

        transporter.sendMail(mailOption, (error, info)=>{
            if(error) return res.status(500).json({message: 'Something went wrong'});

            res.status(200).json({message: 'otp has been sent on email',});
        })


        //res.status(200).json({message: 'success', data: 'response'});
       //res.status(200).json({message: 'otp has been sent on email',});
    }
    catch(error){
        res.status(500).json({message: 'internal server error'});
        console.log(error);
    }
}

const updateUserPassword=async(req,res)=>{
    try{
        console.log(req.params)
        console.log(req.body)
        const { oldPassword, newPassword, otpData, reqEmail } = req.body;
        const userExist=await User.findOne({_id:req.params.id});
        // if (!userExist) {
        //     return res.status(404).json({ message: 'User not found' });
        // }
        const isMatch = await bcrypt.compare(oldPassword, userExist.password);
        
        if(! otpData) return res.status(400).json({message: 'please send otp'});

        //console.log(Number(req.body.otp), newpassword, otpStore.get(reqEmail));

        if(Number(otpData) !== otpStore.get(reqEmail)) return res.status(401).json({message: 'please send valid otp'});
        if (!isMatch) return res.status(401).json({ message: 'Please provide a valid password' });

        
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
        const response = await User.updateOne(
            {
                _id: req.params.id
            },
            {
                $set: {
                    password: hashedPassword
                }
            }
         )
            
    
            res.status(200).json({message:'success',data: response })
      
    }
    catch(error){
        res.status(500).json({message: 'internal server error'});
        console.log(error);
    }
}

const verifyEmail=async(req,res)=>{
    try{
        const {email,otp}=req.body
        if(Number(otp) !== otpStore.get(email)) return res.status(401).json({message: 'please send valid otp'});
        res.status(200).json({message:'success' })
    }
    catch(error){
        res.status(500).json({message: 'internal server error'});
        console.log(error);
    }
}
const userLoginOtp=async(req,res)=>{
    try{
        console.log(req.body)
        const {email,otp}=req.body

               // if(userExist) return res.status(403).json({message:'Email Id already Exist'})
        
        if(Number(otp) !== otpStore.get(email)) return res.status(401).json({message: 'please send valid otp'});
        
        const userExist=await User.findOne({email});

        if(userExist){
            const filePath = `${req.protocol}://${req.get('host')}/user/user-profileimage/`;

            jwt.sign(userExist._doc, process.env.JWT_KEY, { expiresIn: 60 * 60 * 24 * 7 }, (error, token) => {
                console.log(error)
                if (error) return res.status(500).json({ message: 'something went wrong' });
                res.status(200).json({ message: 'success', data: userExist, auth: token,path:filePath, loginStatus:'OTP' });
            })

        }else{
            const dataToSave = new User({
                email
            });
            const response = await dataToSave.save();
            const filePath = `${req.protocol}://${req.get('host')}/user/user-profileimage/`;
            const userFind=await User.findOne({email});

            jwt.sign(userFind._doc, process.env.JWT_KEY, { expiresIn: 60 * 60 * 24 * 7 }, (error, token) => {
                console.log(error)
                if (error) return res.status(500).json({ message: 'something went wrong' });
                res.status(200).json({ message: 'success', data: userFind, auth: token,path:filePath });
            })

        }
        

    }
     catch(error){
        res.status(500).json({message: 'internal server error'});
        console.log(error);
    }
}

const userEmailCheck=async(req,res)=>{
    try{
        const {email}=req.body;
        const userExist=await User.findOne({email});
        if(!userExist) return res.status(404).json({message:'Email Id does not exist'})
        if(userExist){
            const filePath = `${req.protocol}://${req.get('host')}/user/user-profileimage/`;

            jwt.sign(userExist._doc, process.env.JWT_KEY, { expiresIn: 60 * 60 * 24 * 7 }, (error, token) => {
                console.log(error)
                if (error) return res.status(500).json({ message: 'something went wrong' });
                res.status(200).json({ message: 'success', data: userExist, auth: token,path:filePath });
            })
           
        }
    }
    catch(error){
        res.status(500).json({message: 'internal server error'});
        console.log(error);
    }
}
const googleUserRegister=async(req,res)=>{
    try{
        const {name,email}=req.body;
        const dataToSave = new User({
            name,
            email
        });
        const response = await dataToSave.save();

        const userExist=await User.findOne({email: req.body.email }); // findOne-it returns an object
        
        if(!userExist) return res.status(403).json({message:'Email Id does not exist'})

        const filePath = `${req.protocol}://${req.get('host')}/user/user-profileimage/`;

        jwt.sign(userExist._doc, process.env.JWT_KEY, { expiresIn: 60 * 60 * 24 * 7 }, (error, token) => {
            console.log(error)
            if (error) return res.status(500).json({ message: 'something went wrong' });
            res.status(200).json({ message: 'success', data: userExist, auth: token,path:filePath });
        })

        // res.status(200).json({message:'success',data: response })
    }
    catch(error){
        res.status(500).json({message: 'internal server error'});
        console.log(error);
    }
}
const forgotPassword=async(req,res)=>{
    try{
        
        const {email,password}=req.body;
        const userExist=await User.findOne({email});
       
        if (!userExist) {
            return res.status(404).send('User not found');
        }
        // if (password !== cpassword) {
        //     return res.status(400).json({ error: "Passwords do not match" });
        // }

        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const response = await User.updateOne(
            {
                _id: userExist._id
            },
            {
                $set: {
                    password: hashedPassword
                }
            }
         )
            
    
        res.status(200).json({message:'success',data:response })
      
    }
    catch(error){
        res.status(500).json({message: 'internal server error'});
        console.log(error);
    }
}

module.exports={
    userRegister,
    userLogin,
    viewUserData,
    genrateOtpToUpdate,
    updateUserData,
    updateUserPassword,
    verifyEmail,
    userLoginOtp,
    userEmailCheck,
    googleUserRegister,
    forgotPassword
}