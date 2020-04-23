document.getElementById("collapseOnesubmit").addEventListener("click",
async function fetchAsync () {
     event.preventDefault();
//    let attacker = document.getElementById('attacker');
    let target = document.getElementById('target');
    let payload = {
        // attacker: attacker.value,
        //  target: target.value,
        dummy: 'not-required'
    };
    let response = await fetch('/nmap',
        {
            method: 'POST',
            body: JSON.stringify(payload),
            cache: "no-cache",
            headers: new Headers
            ({
                "content-type": "application/json"
            })
        })
    let data = await response.json()
        .then(data => {
            console.log(data);
            string = JSON.stringify(data, undefined, 2);
            $('#collapseOne_response').html(string)
            // $('#mytree').jsonPathPicker(data)
//            $('#mytree').html(data)
              
        })

    .catch(reason => console.log(reason.message))
})

document.getElementById("collapseTwosubmit").addEventListener("click",
async function fetchAsync () {
     event.preventDefault(); 
//    let attacker = document.getElementById('attacker');
    let target = document.getElementById('target');

    let payload = {
        // attacker: attacker.value,
        //  target: target.value,
        dummy: 'not-required'
    };

    let response = await fetch('/headers',
        {
            method: 'POST',
            body: JSON.stringify(payload),
            cache: "no-cache",
            headers: new Headers
            ({
                "content-type": "application/json"
            })
        })
    let data = await response.json()
        .then(data => {
            console.log(data);
            string = JSON.stringify(data, undefined, 2);
            $('#collapseTwo_response').html(string)
            // $('#mytree').jsonPathPicker(data)
//            $('#mytree').html(data)
              
        })

    .catch(reason => console.log(reason.message))
})

document.getElementById("collapseThreesubmit").addEventListener("click",
function submitlaunch() {
    event.preventDefault()
   // let target = document.getElementById('target');

    let entry = {
        // attacker: attacker.value,
        //  target: target.value,
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
           if (response.status !== 200) {
               console.log('Bad Response: $(response.status)');
               $('#errorAlert').text('Bad HTTP Response').show();
               return;
           }
           response.json().then(function (data) {
               if (data.result == 'success') {
                   $('#errorAlert').hidden;
                   $('#successAlert').text(data.message).show();
               } else {
                   $('#successAlert').hidden;
                   $('#errorAlert').text(data.message).show();
               }

               console.log(data)
           })
       })
})

document.getElementById("collapseFoursubmit").addEventListener("click",
function submitsend() {
    event.preventDefault()
   function handleResponseStatusAndContentType(response) {
       const contentType = response.headers.get('content-type');

       if (response.status === 401) throw new Error('Request was not authorized.');

       if (contentType === null) return new Promise(() => null);
       else if (contentType.startsWith('application/json')) {
           response = response.json()
               .then((data) => {
                   $('#errorAlert').text(data.message).show();
                   console.log(response)
               })
       } else if (contentType.startsWith('text/plain')) {
           response = response.text()
               .then((response) => {
                   $('#collapseFour_output').html(response)
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