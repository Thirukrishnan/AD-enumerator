# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""
import subprocess
def run(cmd):
    pipe = subprocess.getstatusoutput(["powershell","-Command", cmd])
    return pipe

cmd="Import-Module .\Microsoft.ActiveDirectory.Management.dll ; Import-Module .\ActiveDirectory.psd1 ;"
enum_cmd=["Get-ADDomain","Get-ADDomainController","net group /domain","get-ADUser -Filter 'Description -like \"*\"' -properties description | select name, description","Get-ADTrust -Filter *"  ]
title=['echo "Domain `n"','echo "Domain Controller `n" ','echo "Domain Groups `n"','echo "Description `n"','echo "Domain Trust `n"']
cmd_str=""

user_cmd="Get-AdUser -Filter * | ?{ $_.Enabled -eq 'true' } | select samAccountName "
computer_cmd="Get-ADComputer -Filter {enabled -eq $true} -properties *|select Name, DNSHostName, OperatingSystem, LastLogonDate,lastLogon, IPv4Address"
active_hosts=""
separator='echo "--------------------------------------------------------------------------------------------`n"'

for i in range(0,len(enum_cmd)):
    if i!=len(enum_cmd)-1:
        cmd_str+=title[i]+";"+enum_cmd[i]+";"+separator+";"
    else:
        cmd_str+=title[i]+";"+enum_cmd[i]+";"+separator

cmd+=cmd_str
err,resp1=run(cmd)
print(resp1)