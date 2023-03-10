#!/usr/bin/env python3
import argparse
import pandas
import awswrangler as wr
import sys, boto3, botocore, json
import ast


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

    list_of_jsons = (wr.s3.read_parquet(path=s3_path, path_suffix=".gz.parquet")).to_json(orient='records', lines=True, compression='gzip').split("\n")
    #Read parquet from S3, turn it into JSON and send it to AnalysisD
    for event_str in list_of_jsons:
        event = json.loads(event_str)
        #sendToAnaylisisD(event)
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
