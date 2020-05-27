##query.py
##python3.7
##DCS 9/12/18
##Work@Crowdstrike

#query.py: as a detection is read, query API will see if it is from an EC2 instance and return relevant data

from time import sleep
import threading


class AWSQuery():
    def __init__(self,logger,ec2_queue,cache):
        self.logger = logger
        self.ec2_queue = ec2_queue
        self.cache = cache

    def main(self, check_queue):
    # main will contain an infinite loop that will listen for events on the Queue
    # and process them
        while True:
            sleep(.1)
            if check_queue.empty():
                pass
            else:
                detection_event = check_queue.get()
                t = threading.Thread(target=self.networkMatch, args =(detection_event,self.ec2_queue))
                t.start()

    def networkMatch(self, detection_event, ec2_queue):
    # networkMatch will get all MACs and IPs from EC2 and see if there is an input match
    # @params MAC: the mac mac address that will be checked
    # @params IP: the public ip that will be checked
    # @returns None
        #check our cache
        val = self.cache.get(detection_event[0])
        if(val):
            print("Match send to builder")
            self.builder(val,ec2_queue,detection_event[1])
        return
    def builder(self,inst,ec2_queue,detection_event):
    # builder will receive instance data, and extract relevant features
    # @params an boto3 instance
    # @returns NONE
        #[accountID, instanceID, Placement Zone, Private IP]
        ec2_queue.put([inst[1], inst[2], inst[3], inst[0], detection_event])
        print("Adding to ec2_queue")
        return
