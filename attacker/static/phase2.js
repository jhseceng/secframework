

document.getElementById("falconInstallSubmit").addEventListener("click",
async function installFalconasync () {
     event.preventDefault();

    // let time_interval = document.getElementById('time_interval').value;
    empty_array = []
    let package_name = $('#package_name').val();
    let action = $('#action').val();
    let instance_ids = $('#instance_ids').val();
    let document_name = $('#document_name').val();
    if (instance_ids.length == 0) {
        alert('Please select an AWS instance')
        return
    }
    $('#install_falcon_out')[0].style.visibility="hidden"
    //$('#query_vpc_out')[0].style.display = "none"
    document.getElementById("spinnerfalconinstall").style.visibility = "visible";

    let payload = {
        package_name: package_name,
        action: action,
        instance_ids: instance_ids,
        document_name: document_name
    };
    try {
        const response = await fetch('/installfalcon',
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
                document.getElementById("spinnerfalconinstall").style.visibility = "hidden";
                $('#install_falcon_response').html(data.Result);
                //$('#query_vpc_out')[0].style.display = "block"
                $('#install_falcon_out')[0].style.visibility = "visible"
            }
        )
    }
    catch{
        console.log('error in fetching posts')
    }
})




