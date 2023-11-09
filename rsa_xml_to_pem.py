import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import xml.etree.ElementTree as ET

def convert_xml_to_pem(private_key_xml_content: str, public_key_xml_content: str):
    # Load private key from XML
    private_key_data = ET.fromstring(private_key_xml_content)
    public_key_data = ET.fromstring(public_key_xml_content)
    inverseQ = int.from_bytes(base64.b64decode(private_key_data.find('InverseQ').text), 'big')
    modulus = int.from_bytes(base64.b64decode(private_key_data.find('Modulus').text), 'big')
    p = int.from_bytes(base64.b64decode(private_key_data.find('P').text), 'big')
    inverseQmodP = inverseQ % p
    exponent = int.from_bytes(base64.b64decode(public_key_data.find('Exponent').text), 'big')
    public_numbers = rsa.RSAPublicNumbers(exponent, modulus)
    private_key = rsa.RSAPrivateNumbers(
        p,
        int.from_bytes(base64.b64decode(private_key_data.find('Q').text), 'big'),
        int.from_bytes(base64.b64decode(private_key_data.find('D').text), 'big'),
        int.from_bytes(base64.b64decode(private_key_data.find('DP').text), 'big'),
        int.from_bytes(base64.b64decode(private_key_data.find('DQ').text), 'big'),
        inverseQmodP,
        public_numbers,
        # int(private_key_data.find('InverseQ').text, 16)
    ).private_key(default_backend())

    private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

    # Load public key from XML
    # public_key_data = ET.fromstring(public_key_xml_content)
    public_key = public_numbers.public_key(default_backend())

    public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    return private_key_pem, public_key_pem


