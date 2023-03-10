#!/usr/bin/env python3
import argparse
import awswrangler as wr
import sys, boto3, json
import socket
import os

def find_wazuh_path() -> str:
    """
    Get the Wazuh installation path.

    Returns
    -------
    str
        Path where Wazuh is installed or empty string if there is no framework in the environment.
    """
    abs_path = os.path.abspath(os.path.dirname(__file__))
    allparts = []
    while 1:
        parts = os.path.split(abs_path)
        if parts[0] == abs_path:  # sentinel for absolute paths
            allparts.insert(0, parts[0])
            break
        elif parts[1] == abs_path:  # sentinel for relative paths
            allparts.insert(0, parts[1])
            break
        else:
            abs_path = parts[0]
            allparts.insert(0, parts[1])

    wazuh_path = ''
    try:
        for i in range(0, allparts.index('wodles')):
            wazuh_path = os.path.join(wazuh_path, allparts[i])
    except ValueError:
        pass

    return wazuh_path


def get_sqs_client(access_key=None, secret_key=None, region=None, profile_name=None):
    conn_args = {}
    conn_args['region_name'] = region

    if access_key is not None and secret_key is not None:
        conn_args['aws_access_key_id'] = access_key
        conn_args['aws_secret_access_key'] = secret_key
    elif profile_name is not None:
        conn_args['profile_name'] = profile_name

    boto_session = boto3.Session(**conn_args)

    try:
        sqs_client = boto_session.client(service_name='sqs')
    except Exception as e:
        print("Error getting SQS client: {}".format(e))
        sys.exit(3)

    return sqs_client


def fetch_message_from_queue(sqs_client, sqs_queue: str):
    print(f'DEBUG: Fetching notification from: {sqs_queue}')
    msg = sqs_client.receive_message(QueueUrl=sqs_queue, AttributeNames=['All'])
    return msg


def get_parquet_location(sqs_client, sqs_queue):
    sqs_message = fetch_message_from_queue(sqs_client, sqs_queue)
    print(f'DEBUG: Message received is: {sqs_message}')
    body = sqs_message['Messages'][0]['Body']
    print(f'DEBUG: Body message is: {body}')
    message = json.loads(body)
    parquet_path = message["detail"]["object"]["key"]
    bucket_path = message["detail"]["bucket"]["name"]
    path = "s3://"+bucket_path+"/"+parquet_path
    return path


def process_events_in_s3(s3_path):
    asl_events_df = wr.s3.read_parquet(path=s3_path, path_suffix=".gz.parquet")
    asl_events = [row.to_json() for row in asl_events_df.iloc]
    wazuh_path = find_wazuh_path()
    wazuh_queue = '{0}/queue/sockets/queue'.format(wazuh_path)

    for event in asl_events:
        send_msg(msg=event,msg_header="1:Wazuh-AWS:", wazuh_queue=wazuh_queue, dump_json=False)
        print("Event -->", event)


def update_security_lake():
    sqs = get_sqs_client()
    paths_from_notifications = fetch_message_from_queue(sqs)
    for path in paths_from_notifications:
        process_events_in_s3(path)


def get_script_arguments():
    parser = argparse.ArgumentParser(usage="usage: %(prog)s [options]",
                                     description="ASL PoC script",
                                     formatter_class=argparse.RawTextHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-q', '--queue', dest='sqs_queue', help='Specify the SQS queue URL containing the notifications',
                       action='store')

    parsed_args = parser.parse_args()

    return parsed_args


def send_msg(msg, msg_header, wazuh_queue, dump_json=True):
        """
        Sends an AWS event to the Wazuh Queue

        :param msg: JSON message to be sent.
        :param dump_json: If json.dumps should be applied to the msg
        """
        try:
            json_msg = json.dumps(msg, default=str)
            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            s.connect(wazuh_queue)
            s.send("{header}{msg}".format(header=msg_header,
                                          msg=json_msg if dump_json else msg).encode())
            s.close()
        except socket.error as e:
            if e.errno == 111:
                print("ERROR: Wazuh must be running.")
                sys.exit(11)
            elif e.errno == 90:
                print("ERROR: Message too long to send to Wazuh.  Skipping message...")
            else:
                print("ERROR: Error sending message to wazuh: {}".format(e))
                sys.exit(13)
        except Exception as e:
            print("ERROR: Error sending message to wazuh: {}".format(e))
            sys.exit(13)


def main():
    options = get_script_arguments()

    try:
        client = get_sqs_client()
        print(f'DEBUG: Retrieving notifications from: {options.sqs_queue}')
        parquet_path = get_parquet_location(client, options.sqs_queue)
        parquets = process_events_in_s3(parquet_path)

    except Exception as err:
        print("ERROR: {}".format(err))
        sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print("Unknown error: {}".format(e))
        sys.exit(1)
