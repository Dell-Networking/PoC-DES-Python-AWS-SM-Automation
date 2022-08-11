# A Basic Example of SONiC Automation with Python3 and AWS Secrets Manager

This repo contains a basic example of how to store access credentials for a SONiC device in AWS Secrets Mananger and then retrieve those creds to carry out a logical VLAN create operation against the switch.

The code in this repo was built and tested on a Linux machine - it may work on MacOS but has not been tested. The Python file may be run on Windows but the setup.sh script will of course not work on Windows without a Bash interpreter. 

### Requirements

Note that the following pre-requisites are required:

  * An AWS account with a secret stored in AWS secrets manger in the form of 'sonic_username: username' and 'sonic_password: password'
    * NOTE: the secret should be created as 'other type of secret' in AWS SM      
  * AWS credentials stored in ~/.aws/credentials - make note of the profile name if not default
  * Python 3.6 or newer
  * pip3 22.2.2 or newer
  * A SONiC system against which to operate against - this can be a physical device or a virtual machine
    * NOTE: this code has only been tested against Enterprise SONiC 3.5.1-Enterprise_base and will very likely NOT work with Enterprise SONiC 4.0+ (due to API changes) or the community version

The setup script (setup.sh) may be used to install Python requirements and activate the virtual environment.

### Running the Python code

At the command line, after installing the python requirements simply run call the main.py file in the form of:

`python3 main.py --aws_profile_name {credential name} --aws_region_name {region name} --secret_name {secret name} --vlan_id {vlan ID integer} --switch_ip {IP address}`

for example:
`python3 main.py --aws_profile_name production-aws-account --aws_region_name us-west-1 --secret_name sonic_user_creds --vlan_id 600 --switch_ip 192.168.1.122`

This should successfully create a VLAN on the targeted device. This is of course just example code and can greatly be expanded. I have also been more verbose in the Python code to make things more clear and have intentionally NOT broken functions out into separate python files, again to keep things as clear as possible in this example.
