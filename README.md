# SweetCIDR
An AWS SDK based tool for mapping network components which are accessible for a given CIDR or Ipv4 address.

## Description
SweetCIDR will take a CIDR value like (10.0.0.1/24 OR 0.0.0.0/0) as an input.
The tool will search for all inbound rules in all security groups which use this CIDR to allow traffic.
It than will find all the attached network intefaces to all of those security groups and as result will provide a detailed report.
The report will containe information about all the possible "targets" for this CIDR.
Information such as: 
  1. Destination public\private IP (depends on the input)
  2. InstanceId \ Or other resource information in cases like load balancer
  3. Port\s (Port or range of ports or "All")
  4. Protocol

You can also use Ipv4 address as an input. than the tool will try generate CIDR variations of this IP.
for example for 10.0.5.78 - the tool will try to search for [10.0.5.78/32, 10.0.5.0/24,  10.0.0.0/16, 10.0.0.0/8].
you can also use the "-a" option, to make the tool generate every possible CIDR the this address belongs to.

For 10.0.5.78 that would be :
['10.0.0.0/8','10.0.0.0/16','10.0.5.0/24','10.0.5.78/32','10.0.0.0/9','10.0.0.0/10','10.0.0.0/11','10.0.0.0/12','10.0.0.0/13','10.0.0.0/14','10.0.0.0/15','10.0.0.0/17','10.0.0.0/18','10.0.0.0/19','10.0.0.0/20','10.0.0.0/21','10.0.4.0/22','10.0.4.0/23','10.0.5.0/25','10.0.5.64/26','10.0.5.64/27','10.0.5.64/28','10.0.5.72/29','10.0.5.76/30','10.0.5.78/31']

## Usage

```usage: SweetCIDR.py [-h] [-s S] [-a] [-nz] [-O O] [-Fn FN] [-alias ALIAS] [-id ID] [-secret SECRET] [-assume ASSUME]

This tool takes IP address or CIDR as an input and lists all the instances that it can talk with according to AWS security group

optional arguments:
  -h, --help      show this help message and exit
  -s S            source IP address or CIDR
  -a              Only when putting an IP not CIDR, By default only variation of /8, /16, /24 and /32 are checked. When this Flag is used, all possible CIDRs are scanned
  -nz             Ignore 0 when generating CIDR list (without 0.0.0.0/0 - Default is to ignore)
  -O O            Output File Path
  -Fn FN          Output File Name
  -alias ALIAS    Account alias to use in output file
  -id ID          AccessKeyId - Needed only to overrite AWS CLI default profile
  -secret SECRET  SecretAccessKey - Needed only to overrite AWS CLI default profile
  -assume ASSUME  AWS role name or ARN (for foreign account) to assume. if STS assume is needed

```

## Examples

```
C:\Users\**\Desktop\Projects\SweetCIDR>SweetCIDR.py -s 0.0.0.0
Scaning now CIDR: 0.0.0.0/0
     processing region ....
     processing region eu-west-1
         processing group named - Allows access to management panel
             processing interface eni-04e**************
             processing interface eni-04e**************
             processing interface eni-04e**************
         processing group named - launch-wizard created 2023-01-31T23:36:15.673Z
             processing interface eni-0b5**************
     processing region ......
         processing group named - launch-wizard-1 created 2023-01-31T23:33:56.724Z
             processing interface eni-0b0**************
             processing interface eni-0b0**************
     processing region us-east-1
         processing group named - launch-wizard-1 created 2022-12-12T04:41:47.456Z
             processing interface eni-006**************
             processing interface eni-006**************
     processing region us-east-2
     processing region us-west-1
     processing region us-west-2

Finished Processing, printing a table of results...

PublicIp        PrivateIp        privateIp  Ports
--------------  -------------  -----------  -------
54.**.**.166  172.31.36.249           81  tcp
54.**.**.166  172.31.36.249           80  tcp
54.**.**.166  172.31.36.249         9005  tcp
34.**.**.43   172.31.38.122           22  tcp
18.**.**.6    172.31.29.82            80  tcp
18.**.**.6    172.31.29.82          3389  tcp
34.**.**.125   172.31.31.3             22  tcp
34.**.**.125   172.31.31.3           8000  tcp
Saved Excel file to 0-0-0-0_11.xlsx
Saved CSV file to 0-0-0-0_11.csv
```
``` CSV result example - 
PublicIp	PrivateIp	instanceId	securityGroupId	groupDescription	Ports	protocol
54.**.**.166	172.31.36.249	ELB app/test-sweetcidr/350*************	sg-04b*************	Allows access to management panel	81	tcp
54.**.**.166	172.31.36.249	ELB app/test-sweetcidr/350*************	sg-04b*************	Allows access to management panel	80	tcp
54.**.**.166	172.31.36.249	ELB app/test-sweetcidr/350*************	sg-04b*************	Allows access to management panel	9005	tcp
34.**.**.43	172.31.38.122	i-052*************	sg-0bc*************	launch-wizard created 2023-01-31T23:36:15.673Z	22	tcp
18.**.**.6	172.31.29.82	i-061*************	sg-055*************	launch-wizard-1 created 2023-01-31T23:33:56.724Z	80	tcp
18.**.**.6	172.31.29.82	i-061*************	sg-055*************	launch-wizard-1 created 2023-01-31T23:33:56.724Z	3389	tcp
34.**.**.125	172.31.31.3	i-042*************	sg-061*************	launch-wizard-1 created 2022-12-12T04:41:47.456Z	22	tcp
34.**.**.125	172.31.31.3	i-042*************	sg-061*************	launch-wizard-1 created 2022-12-12T04:41:47.456Z	8000	tcp
```


## Installation
