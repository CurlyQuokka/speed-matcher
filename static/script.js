function getJson(id) {
    var data = document.getElementById(id);
    var to = data.getElementsByClassName("to")[0].innerText;
    var subject = data.getElementsByClassName("subject")[0].innerText;
    var content = data.getElementsByClassName("content")[0].innerHTML;

    return {
        to: to,
        subject: subject,
        content: content
    }
}

function sendMail(id, errorCounter) {
    var toSend = getJson(id);

    var xhttp = new XMLHttpRequest();
    var url = "/mail";
    xhttp.open("POST", url, true);
    xhttp.setRequestHeader("Content-Type", "application/json");

    toSend["otp"] = document.getElementById("otp").innerText

    xhttp.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            document.getElementById(toSend.to + "-button").disabled = true;
            statusTextField = document.getElementById(toSend.to + "-status");
            statusTextField.innerText = " - wysłano";
            statusTextField.style.color = "green";
        }
        if (this.readyState == 4 && this.status != 200) {
            statusTextField = document.getElementById(toSend.to + "-status");
            statusTextField.innerText = " - WYSTĄPIŁ BŁĄD - " + this.status + " - " + this.statusText + " - " + this.responseText;
            statusTextField.style.color = "red";
            document.getElementById("general-status").innerText += "WYSTĄPIŁ BŁĄD - " + this.status + " - " + this.statusText + " - " + this.responseText + "\n";
            if (errorCounter != null) {
                errorCounter.value++
            }
        }
    };

    var data = JSON.stringify(toSend);
    xhttp.send(data);
}

function sendAll() {
    var results = document.getElementsByClassName("result");

    var errorCounter = {
        value: 0
    };

    for (result of results) {
        id =  result.getElementsByClassName("to")[0].innerText
        sendMail(id, errorCounter)
    }

    if (errorCounter.value == 0) {
        document.getElementById("sendAll-button").disabled = true;
    }
}