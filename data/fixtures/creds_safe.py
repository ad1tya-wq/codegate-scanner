import os
import boto3

def configure_aws():
    return boto3.client("s3")  # relies on default credential chain
