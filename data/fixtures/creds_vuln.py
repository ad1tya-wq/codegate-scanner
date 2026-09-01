import boto3

def configure_aws():
    return boto3.client(
        "s3",
        aws_access_key_id="AKIAZQ3EXJDNVKHRW2LK",
        aws_secret_access_key="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",
    )
