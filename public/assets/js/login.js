const get = (id) => document.getElementById(id);

const username = get("username");
const password = get("password");
const rememberMe = document.getElementById(" customCheckLogin")
const loginSubmit = get("loginSubmit");
const successAlert = get("success_alert");
const errorAlert = get("error_alert");
const successText = get("success_text");
const errorText = get("error_text");

var rem = false;

rememberMe.addEventListener("change", () => {
    if(rememberMe.checked == true){
        rem = true;
    }else{
        rem = false;
    }
})

loginSubmit.addEventListener("click", () => {
    if(username.value==""||password.value==""){
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
    fetch("./api/login", {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username:username.value,
            password:password.value,
            rememberMe:rem
        })
      })
    .then(res => res.json())
    .then(data => {
        if(data.banned == true){
            errorText.innerHTML=`<strong>Error:</strong> Your account is banned!`;
            errorAlert.style.display="block";
            setTimeout(() => {
                errorAlert.style.display="none"
            }, 2500);
            return;
        }else{
            if(data.data == "Logged In Successfully! Redirecting..."){
                successText.innerHTML=`<strong>Success!</strong> Redirecting...`;
                successAlert.style.display="block";
                setTimeout(() => {
                    window.location.assign("/dashboard");
                }, 2500);
                return;
            }else{
                errorText.innerHTML=`<strong>Error:</strong> ${data.data}`;
                errorAlert.style.display="block";
                setTimeout(() => {
                    errorAlert.style.display="none"
                }, 2500);
                return;
            }
        }
    })
})

document.addEventListener("keyup", function(event) {
    if (event.keyCode === 13) {
        loginSubmit.click();
    }
});