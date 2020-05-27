document.getElementById("nmapsubmit").addEventListener("click",
async function fetchAsync () {
     event.preventDefault();
//    let attacker = document.getElementById('attacker');
    document.getElementById("spinnerunnmap").style.visibility = "visible";
    $('#nmap_response').html("")
    let payload = {
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
        await response.json()
            .then(data => {
                document.getElementById("spinnerunnmap").style.visibility = "hidden";
                $('#nmap_response')[0].style.visibility = "visible";
                console.log(data);
                string = JSON.stringify(data, undefined, 2);
                $('#nmap_response').html(string)
        })

    .catch(reason => console.log(reason.message))
})

document.getElementById("Investigatesubmit").addEventListener("click",
async function investigateasync () {
    event.preventDefault();


    // document.getElementById("spinnernmap").style.visibility = "visible";
    try {
        const response = await fetch('/investigate',
            {
                method: 'GET',
                cache: "no-cache",
            })
        await response.text()
            .then((data) => {

                $('#collapseInvestigate3')[0].style.visibility = "visible";
                // document.getElementById("spinnernmap").style.visibility = "hidden";
                document.getElementById("Investigate_response").innerHTML=data
            })
    } catch {
        console.log('error in fetching posts')
    }
})

document.getElementById("headers_submit").addEventListener("click",
async function fetchAsync () {
     event.preventDefault(); 
//    let attacker = document.getElementById('attacker');
//     let target = document.getElementById('target');

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
    await response.json()
        .then(data => {
            $('#headings_output')[0].style.visibility = "visible";
            console.log(data);
            string = JSON.stringify(data, undefined, 2);
            $('#headers_response').html(string)
        })
    .catch(reason => console.log(reason.message))
})


document.getElementById("queryGdSubmit").addEventListener("click",
async function queryGuardDutyasync () {
     event.preventDefault();
     let gdEventsToFilter = $('#guardDutyEventsSelect').val();
     let payload = {
        events_of_interest: gdEventsToFilter

    };
     try {
         const response = await fetch('/gdquery',
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
             .then((res) => {
                 return res.results;
             })
             .then((data) => {
                 for (index = 0; index < data.length; ++index) {
                        datastr = JSON.stringify(data[index])
               jsonView.format(datastr, '.root');
             }})
     }
     catch {
         console.log('error in fetching posts')
     }

})

document.getElementById("queryVpc").addEventListener("click",
async function getVpcFlowasync () {
     event.preventDefault();

     function generateTableHead(table, data) {
            let thead = table.createTHead();
            let row = thead.insertRow();
            for (let index = 2; index <= data.length - 1; index++) {
                    console.log(data[index]);
                    let th = document.createElement("th");
                    let text = document.createTextNode(data[index]);
                    th.appendChild(text);
                    row.appendChild(th);
            }
        }

     function generateTable(table, data) {
            for (let element of data) {
                let fields = element.split(" ")
                let row = table.insertRow();
                for (let index =2; index <=fields.length -1; index++) {
                    let cell = row.insertCell();
                    let text = document.createTextNode(fields[index]);
                    cell.appendChild(text);
                }

            }
        }

    let time_interval = $('#time_interval').val();
    let time_value = $('#time_value').val();
    let query_string = $('#query_string').val();
    let log_group_name = $('#log_group_name').val();
    $("#tableflowlog tr").remove()
    $('#query_vpc_out')[0].style.visibility="hidden";
    $('#query_vpc_out_error')[0].style.visibility = "hidden"

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
                let table_data = data.Headings;
                let table_body = data.logs;
                $('#query_vpc_out')[0].style.visibility = "visible"
                let table = document.getElementById("tableflowlog");
                if (data.logs.length > 0) {
                    generateTableHead(table, table_data)
                    generateTable(table, table_body)
                }
                else {
                    log_data_array = ["No matching logs"]
                    $('#query_vpc_out_error')[0].style.visibility = "visible"
                    document.getElementById("vpcquery_response").textContent = JSON.stringify(log_data_array, undefined, 2);
                }

                document.getElementById("spinnerflowlog").style.visibility = "hidden";

                // $('#query_vpc_out')[0].style.visibility = "visible"
            }
        )
    }
    catch{
        console.log('error in fetching posts')
    }
})


document.getElementById("phase2submit").addEventListener("click",
function startPhase2 () {
    $('.collapse').collapse("hide")
    $('#successAlert').hidden
    $('#errorAlert').hidden
    $('#collapsExploit3').collapse("hide")
    $('#collapseLateral3').collapse("hide")
    $('#Exploit_response').html("")
    $('.multi-collapse4').collapse("show")
})


document.getElementById("phase1-control").addEventListener("click", function showsection1() {
    $('#collapse-section1')[0].style.visibility="visible"
})


