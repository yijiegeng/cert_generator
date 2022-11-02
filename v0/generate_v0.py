from subprocess import Popen, PIPE, STDOUT, DEVNULL
import configparser
import sys
import os

class myconf(configparser.ConfigParser):
    def __init__(self, defaults=None):
        configparser.ConfigParser.__init__(self, defaults=defaults)
    def optionxform(self, optionstr):
        return optionstr


def config(): 
    fname = 'domain.txt'
    # first_line
    with open(fname, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        first_line = lines[0]

    first_line = first_line.strip()
    str = input("domain: {domain}, \n[y/n]:".format(domain=first_line)).lower()
    if str ==  "y" :
        set_configfile(first_line)
    elif str == "n" :
        print('please modify "domain.txt"')
        sys.exit(0)
    else :
        print("invalid answer!")
        sys.exit(0)
    prefix = first_line.split(".", 1)
    return prefix[0]


def set_configfile(domain):
    target_configfile = "app.conf"
    # conf = configparser.ConfigParser()
    conf = myconf() # overwrite "def optionxform()"
    conf.read(target_configfile) 

    if not (conf.has_option("app_info", "commonName") or conf.has_option("app_info", "commonName_default")) :
        print('"app.conf" invalid!')
        sys.exit(0)

    conf.set("app_info", "commonName", domain)
    conf.set("app_info", "commonName_default", domain)
    with open(target_configfile, "w") as f:
        conf.write(f)



def exe_command(commands):
    for command in commands:
        print(command)
        process = Popen(command, stdout=PIPE, stderr=None, shell=True)
        with process.stdout:
            for line in iter(process.stdout.readline, b''):
                print(line.decode().strip())
        exitcode = process.wait()
    return process, exitcode



if __name__=="__main__":
    res = config()
    if os.path.isdir(res):
        if os.path.exists(res + "/app.crt"):
            print ("custom cert exist!")
            sys.exit(0)
    else:
        os.makedirs(res)

    valid_days = 3650
    commands = ["openssl genrsa -out {path}/app.key 2048".format(path=res),
                "openssl req -new -sha256 -out {path}/app.csr -key {path}/app.key -config app.conf".format(path=res),
                "openssl x509 -req -days {days} -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial -in {path}/app.csr -out {path}/app.crt -extfile app.conf".format(days=valid_days, path=res)]

    exe_command(commands)