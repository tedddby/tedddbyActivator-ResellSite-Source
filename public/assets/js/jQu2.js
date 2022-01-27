const get = (id) => document.getElementById(id);


const notifList = get("notificationsList");
const notifsCount = get("notificationsCount");
const userList = get("userList");
const submitUser = get("submitUser");
const editUser = get("submitUsere");


const fetchUsers = () => {
    fetch("/api/users.adm", { method:"post" })
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
                    temp+="<td>"+ele.user_name+"</td>";
                    temp+="<td>"+ele.credits+"</td>";
                    temp+="<td>"+ele.total_unlocked+"</td>";
                    temp+=`<td><button class="btn btn-sm btn-neutral" type="button" onclick="EditUser('${ele.id}')">Edit</button></td>`;
                    temp+=`<td><button class="btn btn-sm btn-neutral" type="button" onclick="DeleteUser('${ele.id}')">Delete</button></td>`;
                    temp+="</tr>";
                })
                userList.innerHTML=temp;
                get("user_count").innerHTML=data.length;
                get("serial_count").innerHTML=6750;
                get("money_count").innerHTML=`$${data.length*10}`
                $('#serialsTable').DataTable();
            }else{
                userList.innerHTML="";
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

const DeleteUser = (id) => {
    if(id){
        fetch("/api/deleteUser.adm", {
            method:"post",
            headers:{
                "Content-Type":"application/json"
            },
            body:JSON.stringify({
                id:id
            })
        })
        .then(res => res.json())
        .then(data => {
            if(data.status == "success"){
                alert("User Deleted!, It will disapper from the table after reload!");
            }else{
                alert("Failed!")
            }
        })
    }else{
        alert("no id")
    }
}

fetchUsers();
fetchNOTIFS();

submitUser.addEventListener("click", () => {
    const username = get("username").value;
    const name = get("name").value;
    const email = get("email").value;
    const password = get("password").value;
    const credits = parseInt(get("credits").value);
    const rank = get("rank").value;
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

    if(username == "" || name == "" || email == "" || password == "" || credits == "" || rank == ""){
        submitUser.style.display="none";
        showLoader();
        setTimeout(() => {
            hideLoader();
            submitUser.style.display="";
            showAlert("danger", "You left some field(s) empty!");
            modal.display="none";
        }, 3000)

        return false;
    }

    submitUser.style.display="none";
    showLoader();
    setTimeout(() => {
        fetch("/api/addUser.adm", {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                info:{
                    username:username,
                    name:name,
                    email:email,
                    password:password,
                    credits:credits,
                    rank:rank
                }
            })
          })
        .then(res => res.json())
        .then(data => {
            if(data.data.includes("successfully!") == true){
                hideLoader();
                submitUser.style.display="";
                showAlert("success", data.data);
                setTimeout(() => {
                    location.reload();
                }, 2000)
                return true;
            }else{
                hideLoader();
                submitUser.style.display="";
                showAlert("danger", data.data);
                return true;
            }
        })
        .catch(err => {
            hideLoader();
            submitUser.style.display="";
            showAlert("danger", err);
            return;
        })
    }, 3000);

})

const refresh = (id) => {
    get(id).innerHTML=` <div class="modal-dialog modal- modal-dialog-centered modal-sm" role="document">
    <div class="modal-content">
      <div class="modal-body p-0">
        <div class="card bg-secondary border-0 mb-0">
          <div class="card-body px-lg-5 py-lg-5">
            <div class="text-center text-muted mb-4">
              <small>Edit User</small>
            </div>
            <form role="form">
              <div class="form-group mb-3">
                <div class="input-group input-group-merge input-group-alternative">
                  <div class="input-group-prepend">
                    <span class="input-group-text"><i class="ni ni ni-circle-08"></i></span>
                  </div>
                  <input class="form-control" placeholder="Username" type="text" id="usernamee">
                </div>
              </div>
              <div class="form-group mb-3">
                <div class="input-group input-group-merge input-group-alternative">
                  <div class="input-group-prepend">
                    <span class="input-group-text"><i class="ni ni ni-circle-08"></i></span>
                  </div>
                  <input class="form-control" placeholder="Name" type="text" id="namee">
                </div>
              </div>
              <div class="form-group mb-3">
                <div class="input-group input-group-merge input-group-alternative">
                  <div class="input-group-prepend">
                    <span class="input-group-text"><i class="ni ni-email-83"></i></span>
                  </div>
                  <input class="form-control" placeholder="Email" type="email" id="emaile">
                </div>
              </div>
              <div class="form-group mb-3">
                <div class="input-group input-group-merge input-group-alternative">
                  <div class="input-group-prepend">
                    <span class="input-group-text"><i class="ni ni-lock-circle-open"></i></span>
                  </div>
                  <input class="form-control" placeholder="Password" type="text" id="passworde">
                </div>
              </div>
              <div class="form-group mb-3">
                <div class="input-group input-group-merge input-group-alternative">
                  <div class="input-group-prepend">
                    <span class="input-group-text"><i class="ni ni-money-coins"></i></span>
                  </div>
                  <input class="form-control" placeholder="Credits" type="number" id="creditse">
                </div>
              </div>
              <div class="form-group">
                <select class="form-control" id="ranke">
                  <option value="">User Rank</option>
                  <option value="ADMIN">Admin</option>
                  <option value="Normal User">Normal User</option>
                </select>
              </div>
              <div class="text-center">
                <button type="button" class="btn btn-primary my-4" id="submitEdit">Edit User</button>
                <div class="lds-dual-ring"style="margin-left: auto;margin-right: auto; display:none;" id="loadere"></div>
                <div class="__none;" role="alert" id="alert_boxe" style='display:none;'>
                  <span class="alert-text" id="alert_texte"></span>
                </div>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  </div>`;
}

const EditUser = (id) => {
    refresh("edit-modal");
    get("edit-toggler").click();
    //===========================//
    const username = get("usernamee")
    const name = get("namee");
    const email = get("emaile");
    const password = get("passworde");
    const credits = get("creditse");
    const rank = get("ranke");
    const alert_box = get("alert_boxe");
    const alert_text = get("alert_texte");
    const loader = get("loadere");
    const submitEdit = get("submitEdit");
    const cls = {
        a: "alert",
        b: "alert-dismissible",
        c: "fade",
        d: "show"
    }

    fetch("/api/userData.adm", {
        method:"post",
        headers:{
            "Content-Type":"application/json"
        },
        body:JSON.stringify({ id:id })
    })
    .then(res => res.json())
    .then(data => {
       if(data.data){
           alert(data.data);
       }else{
        if(data.length == 0){
            alert(JSON.stringify(data))
            alert("Is this a real user?");
            return;
        }else{
            username.value=data.user_name;
            name.value=data.name;
            email.value=data.email;
            password.value=data.password;
            credits.value=data.credits;
            rank.value=data.rank;
        }
       }
    })
    .catch(error => {
        alert(error);
    })

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
    
    submitEdit.addEventListener("click", () => {

        hideAlert();
        hideLoader;

    if(username.value == "" || name.value == "" || email.value == "" || password.value == "" || credits.value == "" || rank.value == ""){
        submitEdit.style.display="none";
        showLoader();
        setTimeout(() => {
            hideLoader();
            submitEdit.style.display="";
            showAlert("danger", "You left some field(s) empty!");
            modal.display="none";
        }, 3000)

        return false;
    }

    submitEdit.style.display="none";
    showLoader();
    setTimeout(() => {
        fetch("/api/editUser.adm", {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                info:{
                    username:username.value,
                    name:name.value,
                    email:email.value,
                    password:password.value,
                    credits:parseInt(credits.value),
                    rank:rank.value,
                    id:id
                }
            })
          })
        .then(res => res.json())
        .then(data => {
            if(data.data.includes("successfully!") == true){
                hideLoader();
                submitEdit.style.display="";
                showAlert("success", data.data);
                setTimeout(() => {
                    location.reload();
                }, 2000)
                return true;
            }else{
                hideLoader();
                submitEdit.style.display="";
                showAlert("danger", data.data);
                return true;
            }
        })
        .catch(err => {
            hideLoader();
            submitEdit.style.display="";
            showAlert("danger", err);
            return;
        })
    }, 3000);

    })
}
