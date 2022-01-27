const express  = require("express");

const controller = require("../controllers/handler.js");

const router = express.Router();

/* GET REQUESTS */

router.get("/", controller.isLoggedIn, (req, res) => {
    if(req.user && req.ipData){
        if(req.user.is_banned == "true"){
            return res.render("login")
        }else{
           if(req.user.rank == "ADMIN"){
            return res.render("AdminDashboard", { user:req.user, geo:req.ipData });
           }else{
            return res.render("dashboard", { user:req.user, geo:req.ipData });
           }
        }
    }else{
        return res.render("login");
    }
});

router.get("/register", controller.isLoggedIn, (req, res) => {
    if(req.user && req.ipData){
        if(req.user.is_banned == "true"){
            return res.render("register")
        }else{
           if(req.user.rank == "ADMIN"){
            return res.render("AdminDashboard", { user:req.user, geo:req.ipData });
           }else{
            return res.render("dashboard", { user:req.user, geo:req.ipData });
           }
        }
    }else{
        return res.render("register");
    }
});

router.get("/dashboard", controller.isLoggedIn, (req, res) => {
    if(req.user && req.ipData){
        if(req.user.is_banned == "true"){
            return res.render("login")
        }else{
           if(req.user.rank == "ADMIN"){
            return res.render("AdminDashboard", { user:req.user, geo:req.ipData });
           }else{
            return res.render("dashboard", { user:req.user, geo:req.ipData });
           }
        }
    }else{
        return res.render("login");
    }
});

router.get("/users", controller.isLoggedIn, (req, res) => {
    if(req.user && req.ipData){
        if(req.user.rank == "ADMIN"){
            return res.render("AdminDashboardUsers", { user:req.user, geo:req.ipData });
        }else{
            return res.render("login");
        }
    }else{
        return res.render("login");
    }
});

router.get("/credits", controller.isLoggedIn, (req, res) => {
    if(req.user && req.ipData){
        if(req.user.is_banned == "true"){
            return res.render("login")
        }else{
           if(req.user.rank == "ADMIN"){
            return res.render("AdminDashboard", { user:req.user, geo:req.ipData });
           }else{
            return res.render("creditPurchase", { user:req.user, geo:req.ipData });
           }
        }
    }else{
        return res.render("login");
    }
});

router.get("/logout", controller.Logout);

router.get("/success/*", (req, res) => {
    return res.redirect("/dashboard")
})

router.get("*", (req, res) => {
    return res.redirect("/dashboard");
})

/*End of GETS*/

//----------------------------------------------------------------------------------------------------------------//

/* POST REQUESTS */
router.post("/api/login", controller.Login);
router.post("/api/register", controller.Register);
router.post("/api/notifications.usr", controller.fetchNotifsUSER);
router.post("/api/serials.usr", controller.fetchSerialsUSER);
router.post("/api/registerSerial.usr", controller.RegisterSerialUSER);
router.post("/api/serials.adm", controller.fetchSerialsAdmin);
router.post("/api/deleteSerial.adm", controller.DeleteSerialAdmin);
router.post("/api/registerSerial.adm", controller.RegisterSerialAdmin);
router.post("/api/session.stjs", controller.GenerateStripeSession);
router.post("/api/users.adm", controller.fetchUsersAdmin);
router.post("/api/deleteUser.adm", controller.DeleteUserAdmin);
router.post("/api/addUser.adm", controller.AddUserAdmin);
router.post("/api/userData.adm", controller.UserDataAdmin);
router.post("/api/editUser.adm", controller.EditUserAdmin);
router.post("/api/deleteRecord.adm", controller.DeleteRecordAdmin);
/* END OF POST REQUESTS */


module.exports = router;