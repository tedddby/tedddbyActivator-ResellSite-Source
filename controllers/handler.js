const mysql = require("mysql");

const env = require("dotenv").config({ path:"./protected.env" });

const jwt = require("jsonwebtoken");

const request = require("request");

const nodemailer = require("nodemailer");

const pwdvalidator = require("password-validator");

const fetch = require("node-fetch");

const envData = process.env;

const stripe = require("stripe")(envData.stripeKey);

const date = new Date();

const dateFormatted = date.toISOString().slice(0,10);

const promisify = f => (...args) => new Promise((a,b)=>f(...args, (err, res) => err ? b(err) : a(res)));

const db = mysql.createConnection({ host:envData.dbHost, database:envData.dbName, user:envData.dbUser, password:envData.dbPassword });

const dbRecords = mysql.createConnection({ host:envData.dbHost, database:"activation_records", user:envData.dbUser, password:envData.dbPassword });

db.connect((e) => { if(e) console.log(e) });

dbRecords.connect((e) => { if(e) console.log(e) });

//1 Login:

const Login = (req, res) => {
    if(req.body){
        try{
            const {username, password, rememberMe} = req.body;
            db.query("SELECT * FROM users WHERE user_name = ? AND password = ?", [username, password], (error, result) => {
                if(error) { console.log(error); return res.status(500).json({ data:"Internal Server Error (Login -1)", banned:false }); }
                else{
                    if(result && result != ""){
                        if(result[0].is_banned == "true"){
                            return res.status(403).json({ data:ban_reason, banned:true });
                        }else{
                            var expToken, expCookie;
                            if(rememberMe == true){
                                expToken = "7d";
                                expCookie = 604800000;
                            }else{
                                expToken = "1h";
                                expCookie = 3600000;
                            }
                            const token = jwt.sign({ id:result[0].id, name:result[0].name, rank:result[0].rank }, envData.JWT_Private_Key, { expiresIn:expToken });
                            if(result[0].rank == "ADMIN"){
                                res.cookie("adminToken", token, { expires:new Date(Date.now()+expCookie), httpOnly:true });
                                res.cookie("authToken", token, { expires:new Date(Date.now()+expCookie), httpOnly:true });
                            }else{
                                res.cookie("authToken", token, { expires:new Date(Date.now()+expCookie), httpOnly:true });
                            }
                            return res.status(200).json({ data:"Logged In Successfully! Redirecting...", banned:false, rank:result[0].rank })
                        }
                    }else{
                        return res.status(401).json({ data:"Invalid Username/Password!", banned:false });
                    }
                }
            })
        }catch{
            return res.status(401).json({ data:"Internal Error", banned:false });
        }
    }else{
        return res.status(401).json({ data:"No Body!", banned:false })
    }
}

//2 Register:

const Register = (req, res) => {
    if(req.body){
        try{
            const {username, email, password, name} =  req.body;
            db.query("SELECT * FROM users WHERE user_name = ?", [username], (error, result) => {
                if(error){
                    return res.status(500).json({ data:"Internal Server Error" });
                }else{
                    if(result && result != ""){
                        return res.status(403).json({ data:"User with this data is already registered!" });
                    }else{
                        if(email == "" || username == "" || password == "" || name == ""){
                            return res.status(401).json({ data:"You left some field(s) Empty!" });
                        }
                        const schema = new pwdvalidator();
                        schema.is().min(6).is().max(100).has().uppercase().has().lowercase();
                        if(schema.validate(password) != true){
                            return res.status(401).json({ data:"Weak password!" })
                        }
                        if(email.includes("@") != true && email.includes(".") != true){
                            return res.status(401).json({ data:"Invalid Email Address!" });
                        }
                        const otp = Math.floor(100000 + Math.random() * 900000);

                        db.query("INSERT INTO users SET ?", [{user_name:username, name:name, password:password, email:email, credits:0, total_unlocked:0, total_failed:0, last_unl:"N/A", last_fail:"N/A", last_purch:"N/A", rank:"Unverified", otp:otp, email_ver:"null", is_banned:"false", ban_reason:"N/A"}], (e, s) => {
                            if(e){
                                return res.status(500).json({ data:"Internal Database Error!" });
                            }else{
                                return res.status(200).json({ data:"User Added Successfully!" })
                            }
                        })
                        /*const sent = SendRegistrationCode(name, email, otp)
                        .then(resc => {
                            if(resc == false){
                                return res.status(500).json({ data:"Couldn't send OTP verification email, Please contact Help Desk!" });
                            }else{
                                db.query("INSERT INTO users SET ?", [{user_name:username, name:name, password:password, email:email, credits:0, total_unlocked:0, total_failed:0, last_unl:"N/A", last_fail:"N/A", last_purch:"N/A", rank:"Unverified", otp:otp, email_ver:"false", is_banned:"false", ban_reason:"N/A"}], (e, s) => {
                                    if(e){
                                        return res.status(500).json({ data:"Internal Database Error!" });
                                    }else{
                                        return res.status(200).json({ data:"User Added Successfully!" })
                                    }
                                })
                            }
                        })*/
                    }
                }
            })
        }catch{
            return res.status(401).json({ data:"Internal Server Error (Register -1)" });
        }
    }else{
        return res.status(401).json({ data:"No Body!" });
    }
}

//3 isLoggedIn:

const isLoggedIn = async (req, res, next) => {
    if(req.cookies.authToken){
        try{
            const decoded = await promisify(jwt.verify)(req.cookies.authToken, envData.JWT_Private_Key);
            const userID = decoded.id;
            db.query("SELECT * FROM users WHERE id = ?", [userID], (error, result) => {
                if(error){
                    return next();
                }else{
                    if(result && result != ""){
                        fetch("http://ip-api.com/json/"+req.ip, { method:"get" })
                        .then(res => res.json())
                        .then(body => {
                            req.ipData = body;
                            req.user = result[0];
                            return next();
                        })
                        .catch(err => {
                            console.log(error);
                            return next();
                        });
                    }else{
                        return next();
                    }
                }
            })
        }catch{
            return next();
        }
    }else{
        return next();
    }
}

//4 isAdmin:

const isAdmin = async (req, res, next) => {
    if(req.cookies.adminToken){
        try{
            const decoded = await promisify(jwt.verify)(req.cookies.adminToken, envData.JWT_Private_Key);
            const userID = decoded.id;
            db.query("SELECT * FROM users WHERE id = ?", [userID], (error, result) => {
                if(error){
                    return next();
                }else{
                    if(result && result != ""){
                        if(result[0].rank == "ADMIN"){
                            req.user = result[0];
                            req.admin = true;
                            return next();
                        }else{
                            return next();
                        }
                    }else{
                        return next();
                    }
                }
            })
        }catch{
            return next();
        }
    }else{
        return next();
    }
}

//5 Verify OTP:

const VerifyOTP = (req, res) => {
    if(req.body){
        try{
            const otpInput = req.body.otp;
            db.query("SELECT * FROM users WHERE otp = ?", [otpInput], (error, result) => {
                if(error){
                    return res.status(500).json({ data:"Internal Database Error!" });
                }else{
                    if(result && result != ""){
                        db.query("UPDATE users SET ? WHERE id = ?", [{email_ver:"true"}, result[0].id], (e,s) => {
                            if(e){
                                return res.status(500).json({ data:"Internal Database Error!" });
                            }else{
                                return res.status(200).json({ data:"You are now verified! Redirecting you to login page..." })
                            }
                        })
                    }else{
                        return res.status(403).json({ data:"Invalid/WRONG OTP number!" });
                    }
                }
            })
        }catch{
            return res.status(500).json({ data:"Internal Server Error! Can't verify your input!" })
        }
    }else{
        return res.status(401).json({ data:"No Body!" });
    }
}

//6 SendOTP [Unexported]:

const SendRegistrationCode = async (name, email, otp) => {
    try{
        let transporter = nodemailer.createTransport({
            host: "mail.tedddby.info",
            port: 25,
            secure: false, 
            auth: {
              user: envData.nodemailerOTPEmail, 
              pass: envData.nodemailerOTPPassword, 
            },
          });
        
          let info = await transporter.sendMail({
            from: '"tedddbyActivator 👻" <otp@tedddby.info>', 
            to: email, 
            subject: "[IMPORTANT]! Please Verify Your Email",
            html: `Hello ${name}
            You registered an account on reselling.tedddby.com, before being able to use your account you need to verify that this is your email address by entering this otp [${otp}] in the registration page.
            Kind Regards, tedddbyActivator`,
          });
          if(info.messageId){
              return true;
          }else{
              return false;
          }
    }catch{
        return false;
    }
}

//7 Fetch SerialNumbers:

const fetchSerialsUSER = async (req, res) => {
    if(req.cookies.authToken){
        try{
            const decoded = await promisify(jwt.verify)(req.cookies.authToken, envData.JWT_Private_Key);
            const name = decoded.name;
            db.query("SELECT * FROM serials WHERE by_user = ?", [name], (error, result) => {
                if(error){
                    return res.status(500).json({ data:"Internal Database Error!" });
                }else{
                    if(result){
                        return res.status(200).send(result);
                    }else{
                        return res.status(500).json({ data:"Internal Database Error!" });
                    }
                }
            })
        }catch{
            return res.status(401).json({ data:"Invalid AuthToken!" });
        }
    }else{
        return res.status(401).json({ data:"Missing Security Token!" });
    }
}

//8 Fetch Notifications:
const fetchNotifsUSER = async (req, res) => {
    if(req.cookies.authToken){
        try{
            const decoded = await promisify(jwt.verify)(req.cookies.authToken, envData.JWT_Private_Key);
            const userID = decoded.id;
            db.query("SELECT * FROM notifications WHERE userID = ?", [userID], (error, result) => {
                if(error){
                    return res.status(500).json({ data:"Internal Server Error!" });
                }else{
                    if(result){
                        return res.status(200).send(result);
                    }else{
                        return res.status(500).json({ data:"Internal Server Error!" });
                    }
                }
            })
        }catch{
            return res.status(401).json({ data:"Invalid AuthToken!" });
        }
    }else{
        return res.status(401).json({ data:"Missing Security Token!" });
    }
}


//9 Register SerialNumber USER:

const RegisterSerialUSER = async (req, res) =>{
    if(req.cookies.authToken){
        try{
            const decoded = await promisify(jwt.verify)(req.cookies.authToken, envData.JWT_Private_Key);
            const userID = decoded.id;
            db.query("SELECT * FROM users WHERE id = ?", [userID], (error, result) => {
                if(error){
                    return res.status(500).json({ data:"Internal Server Error" });
                }else{
                    if(result){
                        const credits = result[0].credits;
                        const name = result[0].name;
                        if(result[0].is_banned == "true"){
                            return res.status(401).json({ data:"Account Banned!" });
                        }else{
                            if(credits == 0){
                                db.query("UPDATE users SET ? WHERE id = ?", [{total_failed:result[0].total_failed+1, last_fail:dateFormatted}, userID], (e,s) => {
                                    if(e){
                                        return res.status(500).json({ data:"Internal Database Error!" });
                                    }else{
                                        return res.status(401).json({ data:"Insufficient Credits, Add some credits then retry!" });
                                    }
                                })
                            }else{
                                if(req.body.serial){
                                    if(req.body.serial.length == 12 && req.body.serial != ""){
                                        if(req.body.service && req.body.service !=""){
                                            const serial = req.body.serial;
                                            const service = req.body.service;
                                            var charge = 0;
                                            switch(service){
                                                case "GSM Bypass" :
                                                    charge = 5;
                                                break;

                                                case "MEID Bypass" :
                                                    charge = 3;
                                                break;

                                                case "MDM Bypass" :
                                                    charge = 5;
                                                break;

                                                case "Carrier Bypass" :
                                                    charge = 5;
                                                break;

                                                default :
                                                    charge = 0;
                                                break;
                                            }
                                            if(charge == 0){
                                                return res.status(401).json({ data:"Invalid Request! Unknow Service!" })
                                            }else{
                                                if(credits-charge < 0){
                                                    return res.status(401).json({ data:"Insufficient Credits, Add some credits then retry! Required Credits:["+charge+"]" });
                                                }else{
                                                    const newCredit=credits-charge;
                                                    const total_unlocked = result[0].total_unlocked+1;
                                                    db.query("UPDATE users SET ? WHERE id = ?", [{credits:newCredit, total_unlocked:total_unlocked, last_unl:dateFormatted}, userID], (r,u) => {
                                                        if(r){
                                                            return res.status(500).json({ data:"Internal Database Error!" })
                                                        }else{
                                                            db.query("INSERT INTO serials SET ?", [{serial:serial, service:service, date:dateFormatted, by_user:name}], (err, resu) => {
                                                                if(err){
                                                                    return res.status(500).json({ data:"Internal Database Error!" });
                                                                }else{
                                                                    return res.status(200).json({ data:"SerialNumber ["+serial+"] registered successfully!" });
                                                                }
                                                            })
                                                        }
                                                    })
                                                }
                                            }
                                        }else{
                                            return res.status(401).json({ data:"Service cannot be empty/or null!" })
                                        }
                                    }else{
                                        return res.status(401).json({ data:"Invalid SerialNumber! Serial cannot be empty or less than 12 digits!" })
                                    }
                                }else{
                                    return res.status(401).json({ data:"Invalid Request! No SerialNumber Provided!" })
                                }
                            }
                        }
                    }else{
                        return res.status(500).json({ data:"Internal Server Error!" });
                    }
                }
            })
        }catch{
            return res.status(401).json({ data:"Invalid AuthToken!" });
        }
    }else{
        return res.status(401).json({ data:"Missing Security Token!" });
    }
}

//10 Logout:

const Logout = async (req, res) => {
    if(req.cookies.authToken){
        try{
            const decoded = await promisify(jwt.verify)(req.cookies.authToken, envData.JWT_Private_Key);
            const userID = decoded.id;
            res.cookie("authToken", "LoggedOut", { httpOnly:true, expires:new Date(Date.now() + 2*1000) });
            return res.redirect("/");
        }catch{
            return res.send("Stop playing with me!")
        }
    }else{
        return res.send("Are you even logged in?")
    }
}

//11 GenerateStripeSession

const GenerateStripeSession = async(req,res) => {
    if(req.cookies.authToken){
        if(req.body.credits){
            if(typeof(req.body.credits) == "number"){
                if(req.body.credits >= 30){
                    try{
                        const decoded = await promisify(jwt.verify)(req.cookies.authToken, envData.JWT_Private_Key);
                        const options = {
                            payment_method_types: ["card"],
                            line_items: [
                                {
                                    price_data: {
                                        currency: "usd",
                                        product_data: {
                                            name: `Panel Credits [${req.body.credits}]`,
                                            description:`Credits for ${decoded.name.toUpperCase()}`
                                        },
                                        unit_amount: parseInt(req.body.credits)*100,
                                    },
                                    quantity: 1,
                                },
                            ],
                            mode: "payment",
                            success_url: `https://reselling.tedddby.com/success/${decoded.id}/${req.body.credits}`,
                            cancel_url: `https://reselling.tedddby.com/credits`,
                        }
                        const session = await stripe.checkout.sessions.create(options);
                        return res.status(200).json({ id:session.id });
                    }catch(e){
                        return res.status(401).json({data:"Unauthorized"})
                    }
                }else{
                    return res.status(401).json({data:"Unauthorized"})
                }
            }else{
                return res.status(401).json({data:"Unauthorized"})
            }
        }else{
            return res.status(401).json({data:"Unauthorized"})
        }
    }else{
        return res.status(401).json({data:"Unauthorized"})
    }
}

//12 Admin Serials:

const fetchSerialsAdmin = async (req, res) => {
    if(req.cookies.adminToken){
        try{
            const decoded = await promisify(jwt.verify)(req.cookies.adminToken, envData.JWT_Private_Key);
            if(decoded.id){
                db.query("SELECT * FROM serials", (e, s) => {
                    if(e){
                        return res.status(500).json({ data:"internal err" });
                    }else{
                        if(s){
                            return res.status(200).send(s);
                        }else{
                            return res.status(500).json({ data:"internal err" });
                        }
                    }
                })
            }
        }catch{
            return res.status(401).json({ data:"not an admin" });
        }
    }else{
        return res.status(401).json({ data:"not an admin" });
    }
}

//12 Admin Users:

const fetchUsersAdmin = async (req, res) => {
    if(req.cookies.adminToken){
        try{
            const decoded = await promisify(jwt.verify)(req.cookies.adminToken, envData.JWT_Private_Key);
            if(decoded.id){
                db.query("SELECT * FROM users", (e, s) => {
                    if(e){
                        return res.status(500).json({ data:"internal err" });
                    }else{
                        if(s){
                            return res.status(200).send(s);
                        }else{
                            return res.status(500).json({ data:"internal err" });
                        }
                    }
                })
            }
        }catch{
            return res.status(401).json({ data:"not an admin" });
        }
    }else{
        return res.status(401).json({ data:"not an admin" });
    }
}

//13 Delete Serial:

const DeleteSerialAdmin = async (req, res) => {
    if(req.cookies.adminToken){
        if(req.body.id){
            try{
                const decoded = await promisify(jwt.verify)(req.cookies.adminToken, envData.JWT_Private_Key);
                if(decoded.id){
                    db.query("DELETE FROM serials WHERE id = ?", [req.body.id], (e, s) => {
                        if(e){
                            return res.status(500).json({ data:"internal err" });
                        }else{
                            if(s){
                                return res.status(200).json({ status:"success" })
                            }else{
                                return res.status(500).json({ data:"internal err" });
                            }
                        }
                    })
                }
            }catch{
                return res.status(401).json({ data:"not an admin" });
            }
        }else{
            return res.status(401).json({ status:"Failed" });
        }
    }else{
        return res.status(401).json({ data:"not an admin" });
    }
}


//14 Register Serial:

const RegisterSerialAdmin = async (req, res) => {
    if(req.cookies.adminToken){
        if(req.body.serial && req.body.service){
            try{
                const decoded = await promisify(jwt.verify)(req.cookies.adminToken, envData.JWT_Private_Key);
                if(decoded.id){
                    db.query("INSERT INTO serials SET ?", [{serial:req.body.serial, service:req.body.service, by_user:`Admin (${decoded.name})`, date:dateFormatted}], (e, s) => {
                        if(e){
                            return res.status(500).json({ data:"internal err" });
                        }else{
                            if(s){
                                return res.status(200).json({ data:"Serial registered successfully!" })
                            }else{
                                return res.status(500).json({ data:"internal err" });
                            }
                        }
                    })
                }
            }catch{
                return res.status(401).json({ data:"not an admin" });
            }
        }else{
            return res.status(401).json({ data:"Failed" });
        }
    }else{
        return res.status(401).json({ data:"not an admin" });
    }
}

//15 Delete Serial:

const DeleteUserAdmin = async (req, res) => {
    if(req.cookies.adminToken){
        if(req.body.id){
            try{
                const decoded = await promisify(jwt.verify)(req.cookies.adminToken, envData.JWT_Private_Key);
                if(decoded.id){
                    db.query("DELETE FROM users WHERE id = ?", [req.body.id], (e, s) => {
                        if(e){
                            return res.status(500).json({ data:"internal err" });
                        }else{
                            if(s){
                                return res.status(200).json({ status:"success" })
                            }else{
                                return res.status(500).json({ data:"internal err" });
                            }
                        }
                    })
                }
            }catch{
                return res.status(401).json({ data:"not an admin" });
            }
        }else{
            return res.status(401).json({ status:"Failed" });
        }
    }else{
        return res.status(401).json({ data:"not an admin" });
    }
}

//15: AddUser:

const AddUserAdmin = async (req, res) => {
    if(req.cookies.adminToken){
        if(req.body.info){
            try{
                const {username, name, email, password, credits, rank} = req.body.info;
                const decoded = await promisify(jwt.verify)(req.cookies.adminToken, envData.JWT_Private_Key);
                if(decoded.id){
                    db.query("INSERT INTO users SET ?", [{user_name:username, name:name, password:password, email:email, credits:credits, total_unlocked:0, total_failed:0, last_unl:"N/A", last_fail:"N/A", last_purch:"N/A", rank:rank, otp:"N/A", email_ver:"N/A", is_banned:"false", ban_reason:"N/A"}], (e, s) => {
                        if(e){
                            return res.status(500).json({ data:"internal err" });
                        }else{
                            if(s){
                                return res.status(200).json({ data:"User "+username+" added successfully!" })
                            }else{
                                return res.status(500).json({ data:"internal err" });
                            }
                        }
                    })
                }
            }catch(e){
                return res.status(401).json({ data:"not an admin" });
            }
        }else{
            return res.status(401).json({ data:"Failed" });
        }
    }else{
        return res.status(401).json({ data:"not an admin" });
    }
}

//16 Admin Users:

const UserDataAdmin = async (req, res) => {
    if(req.cookies.adminToken){
        if(req.body.id){
            try{
                const decoded = await promisify(jwt.verify)(req.cookies.adminToken, envData.JWT_Private_Key);
                if(decoded.id){
                    db.query("SELECT * FROM users WHERE id = ?", [req.body.id], (e, s) => {
                        if(e){
                            return res.status(500).json({ data:"internal err" });
                        }else{
                            if(s){
                                return res.status(200).send(s[0]);
                            }else{
                                return res.status(500).json({ data:"internal err" });
                            }
                        }
                    })
                }
            }catch{
                return res.status(401).json({ data:"not an admin" });
            }
        }else{
            return res.status(401).json({ data:"missing body" });
        }
    }else{
        return res.status(401).json({ data:"not an admin" });
    }
}

//17: EditUser:

const EditUserAdmin = async (req, res) => {
    if(req.cookies.adminToken){
        if(req.body.info){
            try{
                const {username, name, email, password, credits, rank, id} = req.body.info;
                const decoded = await promisify(jwt.verify)(req.cookies.adminToken, envData.JWT_Private_Key);
                if(decoded.id){
                    db.query("UPDATE users SET ? WHERE id = ?", [{user_name:username, name:name, password:password, email:email, credits:credits, rank:rank}, id], (e, s) => {
                        if(e){
                            return res.status(500).json({ data:"internal err" });
                        }else{
                            if(s){
                                return res.status(200).json({ data:"User "+username+" edited successfully!" })
                            }else{
                                return res.status(500).json({ data:"internal err" });
                            }
                        }
                    })
                }
            }catch(e){
                return res.status(401).json({ data:"not an admin" });
            }
        }else{
            return res.status(401).json({ data:"Failed" });
        }
    }else{
        return res.status(401).json({ data:"not an admin" });
    }
}

//18: DeleteRecord:

const DeleteRecordAdmin = async (req, res) => {
    if(req.cookies.adminToken){
        if(req.body.serial){
            try{
                const decoded = await promisify(jwt.verify)(req.cookies.adminToken, envData.JWT_Private_Key);
                if(decoded.id){
                    dbRecords.query("DELETE FROM records WHERE serial = ?", [req.body.serial], (e, s) => {
                        if(e){
                            return res.status(500).json({ data:"internal err" });
                        }else{
                            if(s){
                                return res.status(200).json({ status:"success" })
                            }else{
                                return res.status(500).json({ data:"internal err" });
                            }
                        }
                    })
                }
            }catch{
                return res.status(401).json({ data:"not an admin" });
            }
        }else{
            return res.status(401).json({ status:"Failed" });
        }
    }else{
        return res.status(401).json({ data:"not an admin" });
    }
}


/*Export methods*/
module.exports = {Login, Register, isLoggedIn, isAdmin, VerifyOTP, fetchSerialsUSER, fetchNotifsUSER, RegisterSerialUSER, Logout, GenerateStripeSession, fetchSerialsAdmin, fetchUsersAdmin, DeleteSerialAdmin, RegisterSerialAdmin, DeleteUserAdmin, AddUserAdmin, UserDataAdmin, EditUserAdmin, DeleteRecordAdmin}