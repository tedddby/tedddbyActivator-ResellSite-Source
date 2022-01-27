const get = (id) => document.getElementById(id);

const starterPay = get("starterPay");
const customPrice = get("customPrice");
const customCredits = get("customCredits");
const customCreditsInput = get("customCreditsInput");
const customPay = get("customPay");
const note = get("note");

const stripe = Stripe("pk_live_51JS5eFDJCYp3oML13Lkal4728vX0IVmjnsDoZNwdoDW1XWrCqkKiQazKLUR8pVNv58KIczOFomBUUtfhHopixu0c00blNmprAq");

customCreditsInput.addEventListener("input", () => {
    if(customCreditsInput.value < 31){
        customCreditsInput.value=31;
        note.innerHTML="You can't buy less than 31 Credits in Custom Pack! for that buy Starter Pack";
        note.style.display="";
        customPay.disabled = true;
        return false;
    }else{
        note.style.display="none";
        customPay.disabled=false;
        customCredits.innerHTML=customCreditsInput.value+" Credits";
        if(customCreditsInput.value >= 30){
            customPrice.innerHTML=`$${customCreditsInput.value}`;
        }
    }
})

customPay.addEventListener("click", () => {
    fetch("/api/session.stjs", {
        method:"post",
        headers:{
            "Content-Type":"application/json"
        },
        body:JSON.stringify({
            credits:parseInt(customCreditsInput.value)
        })
    })
    .then(res => res.json())
    .then(session => {
        if(session.id){
            return stripe.redirectToCheckout({sessionId:session.id});
        }else{
            alert("Backend Error! Report this to an Admin");
        }
    })
    .catch(error => alert("Server Error "+error));
})

starterPay.addEventListener("click", () => {
    fetch("/api/session.stjs", {
        method:"post",
        headers:{
            "Content-Type":"application/json"
        },
        body:JSON.stringify({
            credits:parseInt(get("sPrice").innerHTML.replace("$", ""))
        })
    })
    .then(res => res.json())
    .then(session => {
        if(session.id){
            return stripe.redirectToCheckout({sessionId:session.id});
        }else{
            alert("Backend Error! Report this to an Admin");
        }
    })
    .catch(error => alert("Server Error "+error));
})