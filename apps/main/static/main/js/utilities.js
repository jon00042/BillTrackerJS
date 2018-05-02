
function setCsrfToken(xhr) {
    let csrfToken = Cookies.get("csrftoken");
    if (!this.crossDomain) {
        xhr.setRequestHeader("X-CSRFToken", csrfToken);
    }
}

function displayErrors(divTarget, errors) {
    for (let i in errors) {
        let flash = $("<div></div>").addClass("alert alert-danger message")
        flash.text(errors[i])
        flash.appendTo(divTarget)
    }
}

function byteArrayToString(byteArray) {
    var str = "", i;
    for (i = 0; i < byteArray.length; ++i) {
        str += escape(String.fromCharCode(byteArray[i]));
    }
    return str;
}

function shaPwd(password) {
    let shaEncrypted = CryptoJS.SHA256(password);
    return byteArrayToString(shaEncrypted.words);
}

