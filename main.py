import json
import argparse
import ast
import requests
from requests.exceptions import HTTPError
from requests.auth import HTTPBasicAuth
import boto3
import base64
from botocore.exceptions import ClientError


def get_secret(secret_name_query: str, profile_name: str, region_name: str) -> str:
    """
    Query AWS Secrets Manager for a secret based on the name passed under secret_name_query parameter
    :param secret_name_query: Name of the secret to be retrieved
    :param profile_name: Profile name of the AWS profile where AWS credentials are stored
                         file location is typically ~/.aws/credentials
    :param region_name: Name of the AWS region your secret is stored in
    :return: String returned by AWS Secrets Manager - often is JSON but must be parsed as can also be plain text
    """
    global get_secret_value_response
    secret_name = secret_name_query

    # Create a Secrets Manager client
    session = boto3.session.Session(profile_name=profile_name)
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS key.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])

    return get_secret_value_response["SecretString"]


def sonic_create_vlan(vlan_id: int, switch_ip: str, user_name: str, password: str):
    """
        Create a VLAN on a SONiC device via an API call based on the passed VLAN ID
        :param vlan_id: VLAN ID in the form of an integer
        :param switch_ip: IP address of the switch to target for creating the VLAN
        :param user_name: Administrative username for the switch - must have admin level access
        :param password: Password for the specified user
        """
    request_data = {
        "openconfig-interfaces:interface": [
            {
                "config": {
                    "name": f"Vlan{vlan_id}"
                },
                "name": f"Vlan{vlan_id}"
            }
        ]
    }
    print(json.dumps(request_data))
    try:
        response = requests.post(url=f"https://{switch_ip}/restconf/data/openconfig-interfaces:interfaces",
                                 data=json.dumps(request_data),
                                 headers={'Content-Type': 'application/yang-data+json'},
                                 auth=HTTPBasicAuth(f"{user_name}", f"{password}"),
                                 verify=False
                                 )
        response.raise_for_status()

    except HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
    except Exception as err:
        print(f'Other error occurred: {err}')
    else:
        print(f'Success! VLAN {vlan_id} created')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--aws_profile_name", help="AWS profile name to use to pull from Secrets Manager", type=str)
    parser.add_argument("--secret_name", help="Name of the secret to pull from AWS Secrets Manager", type=str)
    parser.add_argument("--aws_region_name", help="Name of the AWS region in which your secret is stored IE: us-west-1", type=str)
    parser.add_argument("--vlan_id", help="VLAN ID to use specified as an integer", type=int)
    parser.add_argument("--switch_ip", help="IP address of the switch to automate", type=str)
    args = parser.parse_args()

    aws_profile_name = args.aws_profile_name  # If no argument is passed for aws_profile_name the default profile will
    # be used if it exists in ~/.aws/credentials

    secret_name = args.secret_name
    vlan_id = args.vlan_id
    switch_ip = args.switch_ip
    aws_region_name = args.aws_region_name

    secret = get_secret(secret_name_query=secret_name, profile_name=aws_profile_name, region_name=aws_region_name)
    dict_secret = ast.literal_eval(secret)
    sonic_username = dict_secret.get("sonic_username")
    sonic_password = dict_secret.get("sonic_password")

    sonic_create_vlan(vlan_id=vlan_id, switch_ip=switch_ip, user_name=sonic_username, password=sonic_password)


if __name__ == '__main__':
    main()
