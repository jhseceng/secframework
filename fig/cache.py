##redis.py
##python 3.7
##DCS 10/16/18
##Work @ Crowdstrike

#redis.py connects to the AWS API and queries accounts for instances twice every 24 hours
#it stores this in a redis db for the gateway to query

from time import sleep
import boto3
import redis
import pickle
import os
import traceback

class Cache():
    def __init__(self,logger):
        self.logger = logger
        self.regions = ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "ap-south-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-north-1", "sa-east-1"]
        self.db = redis.StrictRedis(host='redis', port=6379, db=0)
        try:
            with open("accounts.conf") as f:
                self.accounts = f.readlines()
                self.accounts = [x.strip() for x in self.accounts]
                self.logger.statusWrite("Cache.py got accounts from file: %s" % (self.accounts))
        except:
            self.logger.errorWrite("Unable to read account file exiting....")
            os._exit(0)

    def main(self):
        #main will run in a loop to add IPs and MACs to the cache
        while True:
            #build the database
            self.build()
            #sleep for 12 hours
            sleep(43200)

    def build(self):
        # build is designed to be run once every 12 hours
        # it will query each account and region
        self.refresh()
        self.logger.statusWrite("Buliding Cache")

    def get(self, detection_event):
        #get will check the cache for a matching instacne, on a miss it will check and add if found
        # @params detection_event: the detecion MAC/IP to find
        # @returns
        mac = detection_event[0]
        ip = detection_event[1]
        val = self.db.get(mac)
        if(val):
            val = pickle.loads(self.db.get(mac))
        if(val and (val[0] == ip or val[0] == None)):
            #we have a match
            self.logger.statusWrite("EC2 Match found for: %s, %s" %(mac,ip))

            return val
        else:
            #no match on the cache, lets check the API
            self.build()
            val = self.db.get(mac)
            if(val):
                val = pickle.loads(self.db.get(mac))
            if(val and (val[0] == ip or val[0] == None)):
                #we have a match
                self.logger.statusWrite("EC2 Match found for: %s, %s" %(mac,ip))
                return val
        return None

    def refresh(self):
        sts_client = boto3.client('sts')
        for account in self.accounts:
            self.logger.statusWrite("Processing describe instances for account: %s" % (account))
            try:
                self.assumedRoleObject = sts_client.assume_role(RoleArn=account ,RoleSessionName="AssumeRoleSession1")
                self.credentials = self.assumedRoleObject['Credentials']
                for region in self.regions:
                        self.session = boto3.session.Session
                        self.session = boto3.session.Session(aws_access_key_id = self.credentials['AccessKeyId'],aws_secret_access_key = self.credentials['SecretAccessKey'],aws_session_token = self.credentials['SessionToken'],region_name=region)
                        client = self.session.resource('ec2')
                        insts = list(client.instances.all())
                        for inst in insts:
                            for iface in inst.network_interfaces:
                                info = [inst.private_ip_address,inst.network_interfaces[0].owner_id, inst.instance_id, inst.placement['AvailabilityZone']]
                                try:
                                    self.db.set(iface.mac_address, pickle.dumps(info))
                                    self.logger.statusWrite("Addng mac to db %s" % (iface.mac_address))
                                except:
                                    self.logger.errorWrite("Unable to connect to redis DB is it running? Exiting....")
                                    os._exit(0)
                        self.logger.statusWrite("Connected to AWS API for account %s %s" %(account,region))
            except:
                self.logger.errorWrite("Unable to connect to AWS API for account %s exiting..." %(account))
                traceback.print_exc()
                os._exit(0)
