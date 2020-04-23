import boto3
import json
import sys
import argparse
import requests

EVENTS_OF_INTEREST = ['CryptoCurrency:EC2/BitcoinTool.B!DNS']
def main(arguments):
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('--output_file_name', default='findings_output.txt', required=False)
    args = parser.parse_args(arguments)



    client = boto3.client('guardduty')

    #Find out if GuardDuty already enabled:
    detectors_list = client.list_detectors()

    if not detectors_list["DetectorIds"]:
        print ("GuardDuty is not enabled ... enabling GuardDuty on master account")
        response = client.create_detector(Enable=True);
        # Save DetectorID handler
        DetectorId = response["DetectorId"]
    else:
        print("GuardDuty already enabled on account")
        DetectorId = detectors_list['DetectorIds'][0]

    # print all Detectorts
    print("Detector lists: ")
    for x in detectors_list["DetectorIds"]:
        print(x, end=" ")


    gd_findings = client.list_findings(
        DetectorId=DetectorId
    )

    # print all findings
    _print_finding = lambda DetectorId, FindingId: client.get_findings(
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
        if _find['Findings'][0]['Type'] in EVENTS_OF_INTEREST:
            findings_buffer.append(_find['Findings'][0])

    # print results to a text file
    with open(args.output_file_name, 'w') as outfile:
        json.dump(findings_buffer, outfile)

    # print to terminal (comment out this line if the list is too long, use text file instead)
    print(findings_buffer)

    # print the count of findings for the given severity.
    findings_stat = client.get_findings_statistics(
        DetectorId=DetectorId,
        FindingStatisticTypes=[
            'COUNT_BY_SEVERITY',
        ]
    )

    print('\n\nFindings Statistics: ' + json.dumps(findings_stat['FindingStatistics']))



def header_scan(host):
    headers_dict = {}
    response = requests.get(host)
    headers=response.headers
    for k, v in headers.items():
        print('{}:{}'.format(k,v))
        headers_dict[k] = v
    print(type(headers_dict))
    return


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
    # header_scan('http://v5Jenkins-ALB-1884688024.eu-west-1.elb.amazonaws.com')
