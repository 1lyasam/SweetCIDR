import boto3
import ipaddress
from botocore.config import Config
from datetime import date
import pandas as pd
import argparse
import sys
import os
from os import path
from tabulate import tabulate
import re
# This version gets IP address and checks for all possible subnets sg groups
results = []

def check_file(filePath):
    if path.exists(filePath):
        numb = 1
        while True:
            newPath = "{0}_{2}{1}".format(*path.splitext(filePath) + (numb,))
            if path.exists(newPath):
                numb += 1
            else:
                return newPath
    return filePath

def generate_subnets(ip_address, ignore_first_0=True, all_subnets=False):
    octet_1 = ip_address.split(".")[0]
    octet_2 = ip_address.split(".")[1]
    octet_3 = ip_address.split(".")[2]
    octet_4 = ip_address.split(".")[3]
    CIDR_list = []
    CIDR_list.append(octet_1 + ".0.0.0/8" )
    CIDR_list.append(octet_1 + "." + octet_2 + ".0.0/16")
    CIDR_list.append(octet_1 + "." + octet_2 +  "." + octet_3 + ".0/24")
    CIDR_list.append(ip_address+"/32")
    if all_subnets:
        for cidr in range(32):
            if cidr <8:
                for t in range(int(octet_1)+1):
                    if (t==0 and ignore_first_0==False) or t>0:
                        try:
                            curr_cidr =str(t) +".0.0.0/" + str (cidr)
                            network = ipaddress.IPv4Network(curr_cidr)
                            network_len = network.num_addresses
                            first_address = str(network[0])
                            last_address = str(network[network_len-1])
                        except Exception as ex:
                            print("exception in CIDR")
                            break
                        if int(octet_1) >=int(first_address.split(".")[0]) and int(octet_1)<=int(last_address.split(".")[0]) :
                            #our IP is inside
                            CIDR_list.append(curr_cidr)
                            break
            if cidr >8 and cidr<16:
                for t in range(int(octet_2)+1):
                    try:
                        curr_cidr =octet_1+"."+ str(t) + ".0.0/" + str (cidr)
                        network = ipaddress.IPv4Network(curr_cidr)
                        network_len = network.num_addresses
                        first_address = str(network[0])
                        last_address = str(network[network_len-1])
                    except Exception as ex:
                        print("exception in CIDR")
                    if int(octet_2) >=int(first_address.split(".")[1]) and int(octet_2)<=int(last_address.split(".")[1]) :
                        #our IP is inside
                        CIDR_list.append(curr_cidr)
                        break
            if cidr >16 and cidr<24:
                for t in range(int(octet_3)+1):
                    try:
                        curr_cidr =octet_1+"."+ octet_2 + "." + str(t) +".0/" + str (cidr)
                        network = ipaddress.IPv4Network(curr_cidr)
                        network_len = network.num_addresses
                        first_address = str(network[0])
                        last_address = str(network[network_len-1])
                    except Exception as ex:
                        print("exception in CIDR")
                    if int(octet_3) >=int(first_address.split(".")[2]) and int(octet_3)<=int(last_address.split(".")[2]) :
                        #our IP is inside
                        CIDR_list.append(curr_cidr)
                        break
            if cidr >24 and cidr<32:
                for t in range(int(octet_4)+1):
                    try:
                        curr_cidr =octet_1+"."+ octet_2 + "." + octet_3 + "." + str(t) +"/" + str(cidr)
                        network = ipaddress.IPv4Network(curr_cidr)
                        network_len = network.num_addresses
                        first_address = str(network[0])
                        last_address = str(network[network_len-1])
                    except Exception as ex:
                        print("exception in CIDR")
                    if int(octet_4) >=int(first_address.split(".")[3]) and int(octet_4)<=int(last_address.split(".")[3]) :
                        #our IP is inside
                        CIDR_list.append(curr_cidr)
                        break
    return CIDR_list

def scan_cidr (cidr, account):
    results_local_scan = []
    print("Scaning now CIDR: " + cidr)
    # Describe all Regions in the account
    try:
        if assume:
            client1 = sts_session.client('ec2',region_name="us-east-1")   
        elif account.get("keyId","") == "":
            client1 = boto3.client('ec2',region_name="us-east-1")
        else:
            client1 = boto3.client('ec2', aws_access_key_id=account["keyId"], aws_secret_access_key=account["secret"], region_name="us-east-1")
            
        regions = client1.describe_regions()
        regions = regions["Regions"]
        ec2_regions = regions
    except Exception as e:
        print("Error while extracting regions - {error}".format(error=str(e)))
    for region in regions:
        region_name = region["RegionName"]
        print("     processing region " +region_name)
        try:
            if assume:
                client = sts_session.client('ec2',region_name=region_name)
            elif account.get("keyId","") == "":
                client = boto3.client('ec2',region_name=region_name)
            else:
                client = boto3.client('ec2', aws_access_key_id=account["keyId"], aws_secret_access_key=account["secret"],region_name=region_name)
            response = client.describe_security_groups(Filters=[
                    {
                        'Name': 'ip-permission.cidr',
                        'Values': [
                            cidr,
                        ]
                    }
                    ]
            )
            for group in response.get("SecurityGroups",[]):
                groupId = group.get("GroupId","")
                description = group.get("Description")
                print("         processing group named - " + description)
                #find the relevant rule
                cidr_rules = []
                for rule in group.get("IpPermissions",[]):
                    for cur_cidr in rule.get("IpRanges",[]):
                        if cur_cidr.get("CidrIp","") == cidr:
                            cidr_rules.append(rule)
                describe_network_interfaces = client.describe_network_interfaces( Filters=[
                    {
                        'Name': 'group-id',
                        'Values': [
                            groupId
                        ]
                    }      
                ])
                for relevant_rule in cidr_rules:
                    FromPort = relevant_rule.get("FromPort","")
                    ToPort = relevant_rule.get("ToPort","")
                    if FromPort == ToPort:
                        ports = FromPort
                    else:
                        ports = str(FromPort) + " - " + str(ToPort)
                    if ports == -1:
                        ports = "All"
                    protocol = relevant_rule.get("IpProtocol","")

                    for nic in describe_network_interfaces.get("NetworkInterfaces",""):
                        ip = nic.get("PrivateIpAddress","")
                        nic_id = nic.get("NetworkInterfaceId","")
                        ip_public = nic.get('Association',{}).get("PublicIp","")
                        print("             processing interface " + nic_id)
                        instance_id = nic.get("Attachment",{}).get("InstanceId","")
                        if instance_id == "":
                            instance_id = nic.get("Description","")
                        vpc_id = nic.get("VpcId","")
                        ip_relevant = ip if is_private else ip_public
                        unique_dedup =(str(ip) + str(ports) + str(protocol))
                        if not is_special and (unique_dedup not in dedup):
                            results_local_scan.append({"account":account["name"],"Ip": ip_relevant ,"CIDR": cidr, "instanceId": instance_id, "region":region_name, "securityGroupId":groupId, "groupDescription":description,"Ports": ports, "allowingRule":relevant_rule, "protocol":protocol })
                        elif is_special and (unique_dedup not in dedup): # if 0.0.0.0 both public and private might be relevant for output
                            results_local_scan.append({"account":account["name"],"PublicIp": ip_public,"PrivateIp":ip ,"CIDR": cidr, "instanceId": instance_id, "region":region_name, "securityGroupId":groupId, "groupDescription":description,"Ports": ports, "allowingRule":relevant_rule, "protocol":protocol })
                        dedup.append(unique_dedup)
        
        except Exception as e:
            print("Exception while processing region {regioname} - {exception}".format(regioname=region_name,exception=str(e)))
        region_results_count = str(len(results_local_scan))
        #print("      Found {count} results in the region".format(count=region_results_count))                

    return results_local_scan
                    
if __name__ == "__main__":
    dedup = []
    results = []
    file_name=""
    parser = argparse.ArgumentParser(add_help=True,
                                     description="This tool takes IP address or CIDR as an input and lists all the instances that it can talk with according to AWS security group") 
    parser.add_argument('-s', action='store', help='source IP address or CIDR')
    parser.add_argument('-a', action='store_true',default=False, help='Only when putting an IP not CIDR, By default only variation of /8, /16, /24 and /32 are checked. When this Flag is used, all possible CIDRs are scanned')
    parser.add_argument('-nz', action='store_true',default=True, help='Ignore 0 when generating CIDR list (without 0.0.0.0/0 - Default is to ignore)')
    parser.add_argument('-O', action='store',default="", help='Output File Path')
    parser.add_argument('-Fn', action='store', help='Output File Name')
    parser.add_argument('-alias', action='store',default="AWS account", help='Account alias to use in output file')
    parser.add_argument('-id', action='store', required=False, help='AccessKeyId - Needed only to overrite AWS CLI default profile')
    parser.add_argument('-secret', action='store', required=False, help='SecretAccessKey - Needed only to overrite AWS CLI default profile')
    parser.add_argument('-assume', action='store', required=False, help='AWS role name or ARN (for foreign account) to assume. if STS assume is needed')
    #parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
    try:
       options = parser.parse_args()
    except Exception as e:
       print(str(e))
       sys.exit(1)
    all_cidrs = options.a
    source=options.s
    no_zero = options.nz
    file_path = options.O
    if file_path != "":
        last_char_path = file_path[len(file_path)-1]
        if (os.name == "nt" and last_char_path != "\\") or (os.name != "nt" and last_char_path != "//"):
            if os.name == "nt":
                file_path += "\\"
            else:
                file_path += "/"

    if options.Fn is None:
        file_name = source.replace("/","_").replace(".","-") + ".xlsx"
    else:
        file_name = options.Fn

    aws_account = options.alias
    aws_keyId = options.id
    aws_secret = options.secret
    assume = options.assume
    is_special = False
    account = {"name": aws_account, "keyId":aws_keyId, "secret": aws_secret}
    if assume:
        print("Detected use of assume, trying STS assume role and retreive temporary credentials...")
        if  not "arn:aws" in assume:
            print("Full ARN is missing, Trying to build ARN automatically")
            print("Trying to retreive account Id")
            if account.get("keyId","") == "":
                sts_client = boto3.client("sts")
                acct_id = sts_client.get_caller_identity()["Account"]
                print("Dicovered account ID - " + acct_id)
            else:
                sts_client = boto3.client("sts", aws_access_key_id=account["keyId"], aws_secret_access_key=account["secret"],)
                acct_id = sts_client.get_caller_identity()["Account"]
                print("Dicovered account ID - " + acct_id)
            assume="arn:aws:iam::{account_id}:role/{role_name}".format(account_id=acct_id, role_name = assume)
            print("Succefully assembled role ARN - {arn}".format(arn=assume))
        assume_response = sts_client.assume_role(RoleArn=assume, RoleSessionName="cidr_tool")
        if assume_response.get("Credentials",{}).get("SecretAccessKey","") != "":
            sts_key_id = assume_response.get("Credentials",{}).get("AccessKeyId","")
            sts_secret = assume_response.get("Credentials",{}).get("SecretAccessKey","")
            sts_session = assume_response.get("Credentials",{}).get("SessionToken","")
            print("Succfully assumed role and got temporary keys with ID - {id}".format(id=sts_key_id))
            sts_session = boto3.Session(aws_access_key_id=sts_key_id,
                      aws_secret_access_key=sts_secret,
                      aws_session_token=sts_session)
            
    account = {"name": aws_account, "keyId":aws_keyId, "secret": aws_secret}
    #Check if the IP address is private or public
    x = re.search("\d+\.\d+\.\d+\.\d+",source)
    if x:
        is_private = ipaddress.ip_address(x[0]).is_private
        if x[0] == "0.0.0.0":
            is_special = True
    else:
        print("The parameter -s doesn't contain a valid ipv4 structure, exiting..")
        sys.exit(1)

    if "/" in source:
        try:
            ipaddress.IPv4Network(source)
            results = scan_cidr(source,account)
        except Exception as e:
            print(str(e))
    else:
        try:
            ipaddress.IPv4Address(source)
            cidrs = generate_subnets(source, no_zero, all_cidrs)
            if source == "0.0.0.0":
                cidrs = ["0.0.0.0/0"]
            for cidr in cidrs:
                curr_result = scan_cidr(cidr,account)
                results+=curr_result 
        except Exception as e:
            print(str(e))
    print("")
    print("Finished Processing, printing a table of results... ")  
    print("")
                    
    try:
        df = pd.DataFrame.from_dict(results)
        full_path = check_file(file_path + file_name)
        if not is_special:
            lol = df[["Ip","Ports","protocol"]].values.tolist()
            print(tabulate(lol,["Ip","privateIp","Ports","protocol"],tablefmt="simple"))
        else:
            lol = df[["PublicIp","PrivateIp","Ports","protocol"]].values.tolist()
            print(tabulate(lol,["PublicIp","PrivateIp","privateIp","Ports","protocol"],tablefmt="simple"))
        df.to_excel(full_path)
        print("Saved Excel file to " + full_path)
        full_path = full_path.replace(".xlsx",".csv")
        df.to_csv(full_path)
        print("Saved CSV file to " + full_path)
    except Exception as e:
        print("Exception saving the file " + str (e))
