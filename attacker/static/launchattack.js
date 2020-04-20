    function submitlaunch() {
        let attacker = document.getElementById('attacker');
        let target = document.getElementById('target');

        let entry = {
            attacker: attacker.value,
            target: target.value,
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
    }

    function submitsend() {


        function handleResponseStatusAndContentType(response) {
            const contentType = response.headers.get('content-type');

            if (response.status === 401) throw new Error('Request was not authorized.');

            if (contentType === null) return new Promise(() => null);
            else if (contentType.startsWith('application/json')) return response.json();
            else if (contentType.startsWith('text/plain'))
            {
                response = response.text()
                .then((response) => {
            $('#mydiv').html(response)
            })
            }
            else throw new Error(`Unsupported response content-type: ${contentType}`);
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
    }