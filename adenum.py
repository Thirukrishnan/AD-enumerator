import subprocess
import requests

def check_files():
    cmd="Get-ADDomain"
    err,resp = subprocess.getstatusoutput(["powershell","-Command",cmd])
    if "not recognized" in resp:
        return False
    else:
        return True
def get_files(url,name):
    response=requests.get(url)
    open(name, "wb").write(response.content)
    
def run(cmd):
    pipe = subprocess.getstatusoutput(["powershell","-Command", cmd])
    return pipe
def enum(cmd):
    enum_cmd=["Get-ADDomain","Get-ADDomainController","net group /domain","get-ADUser -Filter 'Description -like \"*\"' -properties description | select name, description","Get-ADTrust -Filter *"  ]
    title=['echo "Domain `n"','echo "Domain Controller `n" ','echo "Domain Groups `n"','echo "Description `n"','echo "Domain Trust `n"']
    cmd_str=""

    user_cmd="Get-AdUser -Filter * | ?{ $_.Enabled -eq 'true' } | select samAccountName "
    computer_cmd="Get-ADComputer -Filter {enabled -eq $true} -properties *|select Name, DNSHostName, OperatingSystem, LastLogonDate,lastLogon, IPv4Address"
    separator='echo "--------------------------------------------------------------------------------------------`n"'

    for i in range(0,len(enum_cmd)):
        if i!=len(enum_cmd)-1:
            cmd_str+=title[i]+";"+enum_cmd[i]+";"+separator+";"
        else:
            cmd_str+=title[i]+";"+enum_cmd[i]+";"+separator

    cmd+=cmd_str
    err,resp1=run(cmd)
    print(resp1)
    
url1="https://raw.githubusercontent.com/samratashok/ADModule/master/ActiveDirectory/ActiveDirectory.psd1"
url2="https://github.com/samratashok/ADModule/blob/master/Microsoft.ActiveDirectory.Management.dll?raw=true"
url3="https://raw.githubusercontent.com/samratashok/ADModule/master/ActiveDirectory/ActiveDirectory.Format.ps1xml"
url4="https://raw.githubusercontent.com/samratashok/ADModule/master/ActiveDirectory/ActiveDirectory.Types.ps1xml"


exist=check_files()
if exist:
    enum(cmd="")
else:
    get_files(url1,"ActiveDirectory.psd1")
    get_files(url2,"Microsoft.ActiveDirectory.Management.dll")
    get_files(url3,"ActiveDirectory.Format")
    get_files(url4,"ActiveDirectory.Types")
    enum(cmd="Import-Module .\Microsoft.ActiveDirectory.Management.dll ; Import-Module .\ActiveDirectory.psd1 ;")
