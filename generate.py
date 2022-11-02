import datetime
import os
import sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# def standardize(s):
#     return s.strip().removeprefix('http://').removeprefix('https://').removesuffix('/')
def standardize(s):
    s = s.strip()
    if s.startswith('http://'):
        s = s[len('http://'):]
    if s.startswith('https://'):
        s = s[len('https://'):]
    if s.endswith('/'):
        s = s[:-1]
    return s


def check_domain(domain):
    if domain == '':
        domain = input("please type domain:\n")
        while domain.strip() == '': domain = input()
        return check_domain(domain)
    else:
        str = input(">>>>>>>>\n {domain} \n>>>>>>>>\n[y/n (q to exit)]:".format(domain=domain)).lower()
        if str == "n":
            domain = input("please type domain:\n")
            while domain.strip() == '': domain = input()
            return check_domain(domain)
        elif str == "q":
            sys.exit(0)
        else:
            return domain


def get_domain():
    fname = 'domain.txt'
    domains = []
    try:
        with open(fname, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            for line in lines:
                domains.append(line)
    finally:
        for idx, domain in enumerate(domains):
            domains[idx] = standardize(domain)

        domain_str = "\n".join(domains) if len(domains) != 0 else ""
        check_domain(domain_str)
        return domains


def generator(domains, prefix):
    root_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    print('<root_key> generated!')
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Jose"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ygeng"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"ygeng"),
    ])
    root_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        root_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(root_key, hashes.SHA256(), default_backend())
    print('<root_cert> generated!')

    # Now we want to generate a cert from that root
    cert_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    print('<cert_key> generated!')
    new_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Jose"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"testAPP"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"testAPP")
    ])
    cert = x509.CertificateBuilder().subject_name(
        new_subject
    ).issuer_name(
        root_cert.issuer
    ).public_key(
        cert_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=90)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]),  # add domain info
        critical=False,
    ).sign(root_key, hashes.SHA256(), default_backend())
    print('<cert> generated!')

    ROOT_CERT_FILE = prefix + '/ca.crt'
    CERT_FILE = prefix + "/app.crt"
    KEY_FILE = prefix + "/app.key"

    # with open(ROOT_CERT_FILE, "wb") as root_cert_file:
    #     root_cert_file.write(root_cert.public_bytes(serialization.Encoding.PEM))

    with open(CERT_FILE, "wb") as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(KEY_FILE, "wb") as key_file:
        key_file.write(cert_key.private_bytes(serialization.Encoding.PEM,
                                              serialization.PrivateFormat.TraditionalOpenSSL,
                                              serialization.NoEncryption()))


if __name__ == "__main__":
    domains = get_domain()
    prefix = "APP_" + domains[0].split(".fortiweb", 1)[0]
    if os.path.isdir(prefix):
        if os.path.exists(prefix + "/app.crt"):
            print("custom cert exist!")
            sys.exit(0)
    else:
        os.makedirs(prefix)
    generator(domains, prefix + '/')
