const get = (id) => document.getElementById(id);

const notifList = get("notificationsList");
const notifsCount = get("notificationsCount");
const serialList = get("serialsList");
const submitSerial = get("submitSerial");

function refreshBody(id){
    var container = document.body;
    var content = container.innerHTML;
    container.innerHTML= content; 
}

const fetchSN = () => {
    fetch("/api/serials.usr", { method:"post" })
    .then(res => res.json())
    .then(data => {
        if(data.data){
            alert(data.data);
            return;
        }else{
            if(data.length > 0){
                var temp ="";
                data.forEach(ele => {
                    temp+="<tr>";
                    temp+="<td>"+ele.serial+"</td>";
                    temp+="<td>"+ele.service+"</td>";
                    temp+="<td>"+ele.date+"</td>";
                    temp+="<td>Registered</td>";
                    temp+="</tr>";
                })
                serialList.innerHTML=temp;
                $('#serialsTable').DataTable();
            }else{
                serialList.innerHTML="";
                $('#serialsTable').DataTable();
            }
        }
    })
    .catch(er => alert(er))
}

const fetchNOTIFS = () => {
    fetch("/api/notifications.usr", { method:"post" })
    .then(res => res.json())
    .then(data => {
        if(data.data){
            alert(data.data);
            return;
        }else{
            if(data.length > 0){
                var temp ="";
                data.forEach(ele => {
                    temp=`<a href="#!" class="list-group-item list-group-item-action">
                    <div class="row align-items-center">
                      <div class="col-auto">
                        <!-- Avatar -->
                        <img alt="Image placeholder" src="assets/img/brand/icon.png" class="avatar rounded-circle">
                      </div>
                      <div class="col ml--2">
                        <div class="d-flex justify-content-between align-items-center">
                          <div>
                            <h4 class="mb-0 text-sm">${ele.title}</h4>
                          </div>
                          <div class="text-right text-muted">
                            <small>${ele.date}</small>
                          </div>
                        </div>
                        <p class="text-sm mb-0">${ele.body}</p>
                      </div>
                    </div>
                  </a>`;
                })
                notifList.innerHTML=temp;
                notifsCount.innerHTML=data.length;
            }else{
                notifsCount.innerHTML=0;
            }
        }
    })
    .catch(er => alert(er))
}

fetchSN();
fetchNOTIFS();

submitSerial.addEventListener("click", () => {
    const serial = get("serialNumber").value;
    const service = get("service").value;
    const alert_box = get("alert_box");
    const alert_text = get("alert_text");
    const loader = get("loader");
    const cls = {
        a: "alert",
        b: "alert-dismissible",
        c: "fade",
        d: "show"
    }
    const modal = get("reg-modal");

    const hideLoader = () => {
        loader.style.display="none";
    }

    const showLoader = () => {
        loader.style.display="";
    }

    const showAlert = (status, text) => {
        alert_box.className="";
        alert_box.classList.add(cls.a);
        alert_box.classList.add("alert-"+status);
        alert_box.classList.add(cls.b);
        alert_box.classList.add(cls.c);
        alert_box.classList.add(cls.d);
        alert_text.innerHTML=text;
        alert_box.style="";
    }

    const hideAlert = () => {
        alert_box.style.display="none";
        alert_box.className="";
    }


    hideAlert();
    hideLoader;

    if(service == "" || serial == ""){
        submitSerial.style.display="none";
        showLoader();
        setTimeout(() => {
            hideLoader();
            submitSerial.style.display="";
            showAlert("danger", "You left some field(s) empty!");
            modal.display="none";
        }, 3000)

        return false;
    }

    if(serial.length != 12){
        submitSerial.style.display="none";
        showLoader();
        setTimeout(() => {
            hideLoader();
            submitSerial.style.display="";
            showAlert("danger", "Invalid Serial Number!");
            modal.display="none";
        }, 3000);

        return false;
    }

    submitSerial.style.display="none";
    showLoader();
    setTimeout(() => {
        fetch("/api/registerSerial.usr", {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                serial:serial,
                service:service
            })
          })
        .then(res => res.json())
        .then(data => {
            if(data.data.includes("successfully!") == true){
                hideLoader();
                submitSerial.style.display="";
                showAlert("success", "Serial Registered!");
                setTimeout(() => {
                    location.reload();
                }, 2000)
                return true;
            }else{
                hideLoader();
                submitSerial.style.display="";
                showAlert("danger", data.data);
                return true;
            }
        })
        .catch(err => {
            hideLoader();
            submitSerial.style.display="block";
            showAlert("danger", err);
            return;
        })
    }, 3000);

})
