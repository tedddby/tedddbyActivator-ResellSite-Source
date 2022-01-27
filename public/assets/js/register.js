const get = (id) => document.getElementById(id);

const username = get("username");
const password = get("password");
const email = get("email");
const name = get("name");
const psw_stren = get("password_stren");
const iAgree = document.getElementById("customCheckRegister")
const registerSubmit = get("registerSubmit");
const successAlert = get("success_alert");
const errorAlert = get("error_alert");
const successText = get("success_text");
const errorText = get("error_text");


const ValidatePassword = (id) => {
    var decimal=  /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9])(?!.*\s).{6,25}$/;
    if(get(id).value.match(decimal)){
        return true;
    }else{
        return false;
    }
}

password.addEventListener("input", () => {
    psw_stren.style.display="block";

    if(password.value==""){
        psw_stren.style.display="none";
    }else{
        if(ValidatePassword("password")){
            psw_stren.innerHTML=`<small>password strength: <span class="text-success font-weight-700">strong</span></small>`;
        }else{
            psw_stren.innerHTML=`<small>password strength: <span class="text-danger font-weight-700">weak</span></small>`;
        }
    }
})

registerSubmit.addEventListener("click", () => {
    if(username.value==""||password.value==""||email.value==""||name.value==""){
        errorAlert.style.display="block";
        errorText.innerHTML=`<strong>Error:</strong> You left some field(s) empty!`;
        setTimeout(() => {
            errorAlert.style.display="none"
        }, 2500);
        return;
    }
    if(username.value.startsWith(`'`)||username.value.startsWith(`"`)){
        errorAlert.style.display="block";
        errorText.innerHTML=`<strong>Error:</strong> Invalid Username!`;
        setTimeout(() => {
            errorAlert.style.display="none"
        }, 2500);
        return;
    }
    if(password.value.startsWith(`'`)||password.value.startsWith(`"`)){
        errorAlert.style.display="block";
        errorText.innerHTML=`<strong>Error:</strong> Invalid Password!`;
        setTimeout(() => {
            errorAlert.style.display="none"
        }, 2500);
        return;
    }
    if(email.value.startsWith(`'`)||email.value.startsWith(`"`)||email.value.includes("@")==false||email.value.includes(".")==false){
        errorAlert.style.display="block";
        errorText.innerHTML=`<strong>Error:</strong> Invalid Email!`;
        setTimeout(() => {
            errorAlert.style.display="none"
        }, 2500);
        return;
    }
    if(name.value.startsWith(`'`)||name.value.startsWith(`"`)){
        errorAlert.style.display="block";
        errorText.innerHTML=`<strong>Error:</strong> Invalid Email!`;
        setTimeout(() => {
            errorAlert.style.display="none"
        }, 2500);
        return;
    }
    get("loader").style.display="";
    registerSubmit.style.display="none";
    fetch("./api/register", {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username:username.value,
            password:password.value,
            name:name.value,
            email:email.value
        })
      })
    .then(res => res.json())
    .then(data => {
        if(data.data != "User Added Successfully!"){
            get("loader").style.display="none";
            registerSubmit.style.display="";

            errorText.innerHTML=`<strong>Error:</strong> ${data.data}`;
            errorAlert.style.display="block";
            setTimeout(() => {
                errorAlert.style.display="none"
            }, 5000);
            return;
        }else{
            get("loader").style.display="none";
            registerSubmit.style.display="";

            successText.innerHTML=`<strong>Success:</strong> ${data.data}`;
                successAlert.style.display="block";
                setTimeout(() => {
                    window.location.assign("/otp-veification");
                }, 2500);
                return;
        }
    })
})

document.addEventListener("keyup", function(event) {
    if (event.keyCode === 13) {
        registerSubmit.click();
    }
});