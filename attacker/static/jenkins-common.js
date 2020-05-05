document.getElementById("exploit_submit").addEventListener("click",
function submitlaunch() {
    event.preventDefault()
    document.getElementById("successAlert").style.display="none";
    document.getElementById("errorAlert").style.display="none";
    document.getElementById("spinner").style.visibility = "visible";
    document.getElementsByClassName("Exploit-output")[0].style.visibility = "collapse";
   // let target = document.getElementById('target');

    let entry = {
        dummy: 'not-required'
    };
   fetch('/launch', {
       method: 'POST',
       body: JSON.stringify(entry),
       cache: "no-cache",
       headers: new Headers({
           "content-type": "application/json"
       })
   })
       .then(function (response) {
           document.getElementById("spinner").style.visibility = "hidden";
           if (response.status !== 200) {
               console.log('Bad Response: $(response.status)');
               $('#errorAlert').text('Bad HTTP Response').show();
               return;
           }
           response.json().then(function (data) {
               if (data.result == 'success') {
                   $('#errorAlert').hidden;
                   $('#successAlert').text(data.message).show();
                   string = JSON.stringify(data, undefined, 2);
                    $('#Exploit_response').html(string);
                    document.getElementsByClassName("Exploit-output")[0].style.visibility = "visible";
               } else {
                   $('#successAlert').hidden;
                   $('#errorAlert').text(data.message).show();
               }

               console.log(data)
           })
       })
})

document.getElementById("send_submit").addEventListener("click",
function submitsend() {
    event.preventDefault()
   function handleResponseStatusAndContentType(response) {
       const contentType = response.headers.get('content-type');

       if (response.status === 401) throw new Error('Request was not authorized.');

       if (contentType === null) return new Promise(() => null);
       else if (contentType.startsWith('application/json')) {
           response = response.json()
               .then((data) => {
                   $('#errorAlertcmd').text(data.message).show();
                   console.log(response)
               })
       } else if (contentType.startsWith('text/plain')) {
           response = response.text()
               .then((response) => {
                   $('#lateral_response').html(response)
               })
       } else throw new Error(`Unsupported response content-type: ${contentType}`);
   }

   let commandselected = $('#cmdtosend').val()
   let entry = {
       cli: commandselected
   };
   val = JSON.stringify(entry)
   fetch('/send', {
       method: 'POST',
       body: JSON.stringify(entry),
       cache: "no-cache",
       headers: new Headers({
           "content-type": "application/json"
       })
   })
       .then(response => handleResponseStatusAndContentType(response))
       .catch(error => {
           console.error(error);
           return error;
       })
})

document.getElementById("queryVpc").addEventListener("click",
async function getVpcFlowasync () {
     event.preventDefault();

    // let time_interval = document.getElementById('time_interval').value;

    let time_interval = $('#time_interval').val();
    let time_value = $('#time_value').val();
    let query_string = $('#query_string').val();
    let log_group_name = $('#log_group_name').val();
    $('#query_vpc_out')[0].style.visibility="hidden"
    //$('#query_vpc_out')[0].style.display = "none"
    document.getElementById("spinnerflowlog").style.visibility = "visible";

    let payload = {
        time_interval: time_interval,
        time_value: time_value,
        query_string: query_string,
        log_group_name: log_group_name
    };
    try {
        const response = await fetch('/vpclogs',
            {
                method: 'POST',
                cache: "no-cache",
                body: JSON.stringify(payload),
                headers: new Headers
                ({
                    "content-type": "application/json"
                })
            })
        await response.json()
            .then((data) => {
                let log_data_array = []
                document.getElementById("spinnerflowlog").style.visibility = "hidden";
                if (data.logs.length > 0) {
                    log_data_array = data.logs
                }
                else {
                    log_data_array = ["No matching logs"]
                }
                document.getElementById("spinnerflowlog").style.visibility = "hidden";
                document.getElementById("vpcquery_response").textContent = JSON.stringify(data, undefined, 2);
                $('#query_vpc_out')[0].style.visibility = "visible"
            }
        )
    }
    catch{
        console.log('error in fetching posts')
    }
})
