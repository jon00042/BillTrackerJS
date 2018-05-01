function makeApiCall(processData) {
    
    $("button").click(function (event) {
        event.preventDefault();
        $(".fa").toggleClass("call");
        let apiUrl = $("input[name=api-url]").val();
        let csrf = $("input[name=csrfmiddlewaretoken]").val();
        $.ajax({
            type: "POST",
            url: $("form").attr("action"),
            data: { 'url': apiUrl, csrfmiddlewaretoken: csrf },
            success: function(response) {
                $(".fa").toggleClass("call");
                processData(JSON.parse(response));
            }
        });
    });
}

function createElement(tag) {
    return $("<"+tag+"></"+tag+">");
}