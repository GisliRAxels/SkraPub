import base64
import zlib
import logging
from logging.handlers import RotatingFileHandler
import os
import traceback
import ecdsa
from cryptography import x509
from hashlib import sha512
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import xml.etree.ElementTree as ET

C40_CHART = {
    "Shift 1": 0,
    "Shift 2": 1,
    "Shift 3": 2,
    " ": 3,
    "0": 4,
    "1": 5,
    "2": 6,
    "3": 7,
    "4": 8,
    "5": 9,
    "6": 10,
    "7": 11,
    "8": 12,
    "9": 13,
    "A": 14,
    "B": 15,
    "C": 16,
    "D": 17,
    "E": 18,
    "F": 19,
    "G": 20,
    "H": 21,
    "I": 22,
    "J": 23,
    "K": 24,
    "L": 25,
    "M": 26,
    "N": 27,
    "O": 28,
    "P": 29,
    "Q": 30,
    "R": 31,
    "S": 32,
    "T": 33,
    "U": 34,
    "V": 35,
    "W": 36,
    "X": 37,
    "Y": 38,
    "Z": 39,
}

REVERSE_C40_CHART = {value: key for key, value in C40_CHART.items()}

def write_error_to_file(error_message, file_path='err.txt'):
    """Skrifar úr error kóða í skrá"""
    try:
        with open(file_path, 'w') as file:
            file.write(error_message)
    except Exception as e:
        logging.error(f"Failed to write error to {file_path}: {e}")

def setup_logging():
    """ Setja upp logger með róteringu"""
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    log_file = os.path.join(os.getcwd(), 'BarcodeDecoder.log')
    handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5) # Rótering,  10mb per skrá,  5 skrár max.  Eftir það deleta elstu.
    handler.setFormatter(log_formatter)

    logger = logging.getLogger('BarcodeDecoderLogger')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)

    return logger

def determine_signature_status(flag):
    '''
    Tákn sem segir til um hvort gögn séu zippuð, og/eða undirrituð.  Hjálpar skriptunni að átta sig á hvaða aðferðir þarf að nota til að vinna úr gögnum.
    
    A = Not signed, Not compressed
    B = Signed, Not compressed
    C = Not signed, Compressed
    D = Signed, Compressed
    
    '''
    if flag in ['A']:
        IsSigned = False
        IsZipped = False
    elif flag in ['B']:
        IsSigned = True
        IsZipped = False
    elif flag in ['C']:
        IsSigned = False
        IsZipped = True
    elif flag in ['D']:
        IsSigned = True
        IsZipped = True
    else:
        error_message ="Invalid flag. Flag must be 'A', 'B', 'C', or 'D"
        write_error_to_file(error_message)
        raise ValueError("Invalid flag. Flag must be 'A', 'B', 'C', or 'D'.")
    
    return IsSigned, IsZipped

def parse_barcode_input(file_path):
    """
    Les strikamerkjagögn úr skrá og skilar sem streng.
    
    :param file_path: Slóð að textaskrá með strikamerkjagögnum.
    :return: Strengur lesinn úr skránni.
    """
    with open(file_path, 'r') as file:
        return file.read().strip()
    
def c40_decode(encoded_bytes):
    """
    Afkóðar C40 kóðuð bytes.
    """
    decoded_string = ""
    shift = None

    for i in range(0, len(encoded_bytes), 2):
        I1 = encoded_bytes[i]
        I2 = encoded_bytes[i + 1]

        V16 = (I1 * 256) + I2

        U1 = (V16 - 1) // 1600
        U2 = (V16 - (U1 * 1600) - 1) // 40
        U3 = V16 - (U1 * 1600) - (U2 * 40) - 1

        for U in [U1, U2, U3]:
            if U == 0:
                shift = 1
            elif U == 1:  
                shift = 2
            elif shift:
                decoded_string += REVERSE_C40_CHART.get((U + (40 * shift)) % 40, "")
                shift = None
            else:
                decoded_string += REVERSE_C40_CHART.get(U, "")

    return decoded_string

def decompress_data(data):
    return zlib.decompress(data)

def base32_decode(encoded_bytes):
    """
    Afkóðar base-32,  en þarf að vera með padding.
    
    """
    return base64.b32decode(encoded_bytes)

def add_base32_padding(encoded_string):
    """
    Bætir við padding á base32 streng.

    Args:
    - encoded_string (str): The Base32 strengur.

    Returns:
    - str: base32 strengur með padding.
    """
    padding_needed = (8 - len(encoded_string) % 8) % 8
    return encoded_string + '=' * padding_needed


def HeadReader(barcode_data, IsSigned):

    """
    Les haus strikamerkis,  
    
    param:  gögnn strikamerkis.
    param:  IsSigned flag sem segir til um hvort gögn séu undirrituð.
    """
    remaining_data = None

    if IsSigned == False:
        if len(barcode_data) < 2:
            error_message ="Barcode data is too short for this flag type in head"
            write_error_to_file(error_message)
            raise ValueError("Barcode data is too short for this flag type.")
        country_identifier = barcode_data[:2]
        remaining_data = barcode_data[2:]

    elif IsSigned == True:
        if len(barcode_data) < 11:
            error_message ="Barcode data is too short for this flag type in head"
            write_error_to_file(error_message)
            raise ValueError("Barcode data is too short for this flag type.")
        country_identifier = barcode_data[:2]
        signature_algorithm = barcode_data[2:3]
        certificate_reference = barcode_data[3:8]
        signature_creation_date = barcode_data[8:12]
        remaining_data = barcode_data[12:]

    else:
        error_message ="Invalid barcode flag"
        write_error_to_file(error_message)
        raise ValueError(f"Invalid barcode flag: {IsSigned}")

    header_data = {
        "Country Identifier": country_identifier,
        "Signature Algorithm": signature_algorithm if IsSigned else None,
        "Certificate Reference": certificate_reference if IsSigned else None,
        "Signature Creation Date": signature_creation_date if IsSigned else None,
        "Remaining Data": remaining_data
    }

    return header_data

def decode_date(encoded_date):
    
    '''
    Afkóðar dagsetningu úr bætum.

    :param encoded_date: Kóðuð dagsetning sem bæti.
    :return: Afkóðuð dagsetning sem strengur á forminu MMDDÁÁÁÁ.
    '''



    # Fjarlægir "date mask"
    relevant_data = encoded_date[1:]
    
    # umbreyta bytes í int
    date_int = int.from_bytes(relevant_data, 'big')

    year = date_int % 10000
    date_int //= 10000
    day = date_int % 100
    month = date_int // 100

    # Format MMDDYYYY
    decoded_date = f"{month:02}{day:02}{year}"
    return decoded_date

def extract_message_zone(data):

    """
    Dregur út "messagezone"

    Skilar;
    þrennt;  innihald messagezone,  rest af gögnum(ef er),  og DER-TLV kóðun á messagezone.
    """

    if len(data) < 2:
        error_message ="message zone data too short"
        write_error_to_file(error_message)
        raise ValueError("Data is too short to contain a valid message zone.")

    # Check for the tag
    tag = data[0]
    if tag != 0x61:
        error_message ="Expected messagezone tag 0x61 not found."
        write_error_to_file(error_message)
        raise ValueError(f"Expected tag 0x61, but found {tag}.")

    # Extract the length
    length_byte = data[1]
    if length_byte & 0x80:  # Long form
        num_length_bytes = length_byte & 0x7F  # Number of subsequent bytes
        if num_length_bytes == 0 or num_length_bytes > len(data) - 2:
            error_message ="Invalid length bytes in DER-TLV encoding of messagezone"
            write_error_to_file(error_message)
            raise ValueError("Invalid length bytes in DER-TLV encoding.")
        length = int.from_bytes(data[2:2 + num_length_bytes], 'big')
        start_index = 2 + num_length_bytes
        length_bytes = data[1:2 + num_length_bytes]  # Include the length byte(s)
    else:  # Short form
        length = length_byte
        start_index = 2
        length_bytes = data[1:2]  # Single length byte

    if start_index + length > len(data):
        error_message ="Not enough data in messagezone"
        write_error_to_file(error_message)
        raise ValueError("Data is truncated or length is incorrect.")

    message_zone = data[start_index:start_index + length]
    remaining_data = data[start_index + length:]

    tag_bytes = tag.to_bytes(1, byteorder='big')
    der_tlv_message_zone = tag_bytes + length_bytes + message_zone

    return message_zone, remaining_data, der_tlv_message_zone

def MessageZoneReader(message_zone):
    index = 0
    message_data = {}

    # Möguleg tög í "MessageZone"
    message_types = {
        0x01: "Visa",
        0x02: "Emergency Travel Document",
        0x03: "Proof of Testing",
        0x04: "Proof of Vaccination",
        0x05: "Proof of Recovery",
        0x06: "Digital Travel Authorization",
        0x07: "Machine Readable Zone (TD1)",
        0x08: "Machine Readable Zone (TD3)",
        0x09: "Card Access Number",
        0x0A: "EF.CardAccess",
        0xAA: "Full Name",
        0xAB: "MicroFace"
    }

    while index < len(message_zone):
        tag = message_zone[index]
        index += 1

        length_byte = message_zone[index]                   
        index += 1

        if length_byte & 0x80:  # Long form
            num_length_bytes = length_byte & 0x7F
            length = int.from_bytes(message_zone[index:index + num_length_bytes], 'big')
            index += num_length_bytes
        else:  # Short form
            length = length_byte

        value = message_zone[index:index + length]
        index += length

        message_type = message_types.get(tag, f"Unknown tag: {tag}")
        message_data[message_type] = value

    return message_data

def decode_message_zone_data(extracted_message_data):
    decoded_data = {}

    for tag, value in extracted_message_data.items():
        if tag == "Machine Readable Zone (TD1)" or tag == "Machine Readable Zone (TD3)":
            # Decode using c40_decode and replace spacebars with '<'
            decoded_value = c40_decode(value).replace(' ', '<')
        elif tag == "Card Access Number":
            decoded_value = c40_decode(value)
        elif tag == "Full Name":
            decoded_value = value.decode('utf-8')
            
        elif tag == "MicroFace":
            # vista sem jp2 og geyma hráu gögnin
            save_image_as_jp2(value, 'MicroFace.jp2')
            decoded_value = value

        else:
            decoded_value = value

        decoded_data[tag] = decoded_value

    return decoded_data

def save_image_as_jp2(image_data, filename):
    directory_path = "C:\\PY\\BarcodeDecodeOutput"
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)

    file_path = os.path.join(directory_path, filename)
    with open(file_path, 'wb') as file:
        file.write(image_data)
        print("Image Data", image_data)
        print("Image Data", image_data.hex())
    print(f"Saved {file_path}")

def SignatureZoneCheck(data, IsSigned, logger):
    if IsSigned:
        if not data:
            logger.error("SignatureZoneCheck: No data found in the signature zone, but IsSigned is True.")
            error_message ="no data in signature zone found but issigned is true"
            write_error_to_file(error_message)
            raise ValueError("No data in signature zone despite IsSigned being True.")
        if data:
            logger.info("SignatureZoneCheck: IsSigned is true and Signature data is present.")
    else:
        if data:
            logger.warning("Data after Messagezone found, but IsSigned is False.")
            logger.info("Remaining data: %s", data.hex())
            print("Warning: Data after Messagezone found, but IsSigned is False.")
            print("Remaining data:", data.hex())
        else:
            logger.info("SignatureZoneCheck: Data passed SignatureZoneCheck.")

def ExtractSignerCertificateZone(data, IsSigned, logger):
    if not IsSigned:
        logger.info("IsSigned is False. Skipping Signer Certificate Zone processing.")
        return None, data

    if not data or data[0] != 0x7E:
        return None, data

    index = 1 
    length_byte = data[index]
    index += 1

    if length_byte & 0x80:  # Long form
        num_length_bytes = length_byte & 0x7F  # Number of subsequent bytes
        if num_length_bytes == 0 or num_length_bytes > len(data) - index:
            logger.error("Invalid length bytes in DER-TLV encoding for Signer Certificate Zone.")
            return None, data

        length = int.from_bytes(data[index:index + num_length_bytes], 'big')
        index += num_length_bytes
    else:  # Short form
        length = length_byte

    if index + length > len(data):
        logger.error("Data is truncated or length is incorrect in Signer Certificate Zone.")
        return None, data

    signer_certificate_data = data[index:index + length]

    remaining_data = data[index + length:]

    return signer_certificate_data, remaining_data

def SignatureReader(data, IsSigned):
    if IsSigned == False:
        if data:
            print("Warning: IsSigned is False but there is remaining data in Signature Zone.")
            print("Remaining Data:", data.hex())
        return None

    if len(data) < 2:
        error_message ="Signature zone data seems to be wrong"
        write_error_to_file(error_message)
        raise ValueError("Data is too short to contain a valid signature zone.")

    tag = data[0]
    if tag != 0x7F:
        raise ValueError(f"Expected tag 0x7F for signature zone, but found {tag}.")

    length_byte = data[1]
    if length_byte & 0x80:  # Long form
        num_length_bytes = length_byte & 0x7F 
        if num_length_bytes == 0 or num_length_bytes > len(data) - 2:
            raise ValueError("Invalid length bytes in DER-TLV encoding.")
        length = int.from_bytes(data[2:2 + num_length_bytes], 'big')
        start_index = 2 + num_length_bytes
    else:  # Short form
        length = length_byte
        start_index = 2

    if start_index + length > len(data):
        raise ValueError("Data is truncated or length is incorrect.")

    signature_zone = data[start_index:start_index + length]

    remaining_data = data[start_index + length:]
    if remaining_data:
        error_message ="Unclear data remaining after signature zone"
        write_error_to_file(error_message)
        print("Warning: Unclear data remaining after signature zone:", remaining_data.hex())

    return signature_zone

def MRZSplitter(mrz_data):
    """
    Skiptir MRZ upp í 3 parta,  býst við lengd 90,  skiptir upp í 30x3

    """
    #
    if len(mrz_data) != 90:
        error_message ="The mrz data needs to be 90 characters.."
        write_error_to_file(error_message)
        raise ValueError("MRZ data must be exactly 90 characters long.")
    
    return mrz_data[:30], mrz_data[30:60], mrz_data[60:]

def write_to_file(mrz_data=None, full_name=None, can=None, logger=None):
    directory_path = "C:\\PY\\BarcodeDecodeOutput"
    file_name = "BarcodeDecodeOutputData.txt"
    full_file_path = os.path.join(directory_path, file_name)

    if not os.path.exists(directory_path):
        os.makedirs(directory_path)

    with open(full_file_path, 'w') as file:
        if mrz_data:
            for line in mrz_data:
                file.write(f"{line}\n")
            file.write(f"{full_name}\n")
        elif can:
            file.write(f"{can}\n")
        else:
            if logger:
                logger.error("Neither MRZ nor CAN found in the data.")

def remove_prefix(barcode_string):

    if len(barcode_string) < 5:
        raise ValueError("Barcode string is too short to extract required information.")
    
    if not barcode_string.startswith("IDB"):
        error_message ="Prefix of barcode is wrong."
        write_error_to_file(error_message)
        raise ValueError("Prefix of barcode is wrong")
    
    barcode_identifier = barcode_string[:4]
    barcode_flag = barcode_string[4]
    updated_data = barcode_string[5:]

    return barcode_identifier, barcode_flag, updated_data

def decode_hex_to_string(hex_string):
    try:
        byte_data = bytes.fromhex(hex_string)
        return byte_data.decode('utf-8')
    
    except ValueError as e:
        print(f"Error during decoding: {e}")
        return None

def get_config_from_xml(file_path):
    config = {}

    tree = ET.parse(file_path)
    root = tree.getroot()

    for child in root:
        config[child.tag] = child.text

    return config

def pem_to_plain_string(pem_path):
    with open(pem_path, 'rb') as pem_file:
        pem_data = pem_file.read()

    public_key = serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    pem_str = pem.decode()
    pem_lines = pem_str.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").split()
    plain_str = ''.join(pem_lines)

    return plain_str


def load_public_key_from_der(der_path):
    with open(der_path, 'rb') as f:
        cert_data = f.read()
    cert = x509.load_der_x509_certificate(cert_data)
    public_key = cert.public_key()
    return public_key

def check_ecdsa_curve_p521(der_path):
    with open(der_path, 'rb') as f:
        cert_data = f.read()
    cert = x509.load_der_x509_certificate(cert_data, default_backend())

    public_key = cert.public_key()
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name
        if curve_name == "secp521r1":
            print(f"The public key uses the P-521 curve. Curve name: {curve_name}")
            return True
        else:
            print(f"The public key does not use the P-521 curve. Curve name: {curve_name}")
            return False
    else:
        print("The public key of:", der_path, " Is not an Elliptic curve key")
        return False
    
def get_public_key_from_der_certificate_as_string(der_certificate_path):
    # Load the DER certificate
    with open(der_certificate_path, 'rb') as file:
        der_certificate_data = file.read()
    
    # Breytir DER-vottorði í x509 hlut
    certificate = x509.load_der_x509_certificate(der_certificate_data, default_backend())
    
    # Nær í opinbera lykilinn úr vottorðinu
    public_key = certificate.public_key()
    
    # Breytir openbera lykilinn í PEM-snið
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Afkóða PEM lykilinn yfir í streng.
    pem_public_key_str = pem_public_key.decode('utf-8')
    
    # Tekur í burtu enda og byrjunarlínur sem er oft í þessum vottorðnum,  þar á meðal þessum.
    pem_public_key_str = pem_public_key_str.replace("-----BEGIN PUBLIC KEY-----\n", "").replace("-----END PUBLIC KEY-----\n", "").strip()

    # Fjarlægir öll línubil sem gætu verið í strengnum.
    pem_public_key_str = pem_public_key_str.replace("\n", "")

    return pem_public_key_str

def main():
    try:
        logger = setup_logging()
        logger.info("")
        logger.info("###  Beginning of script instance  ###")

        #paths
        INPUT_DATA_FILE_PATH = r'C:\PY\BarcodeDecodeInput\BarcodeDecodeRawInput.txt'
        xml_file_path = 'C:\PY\DecodeConfig.xml'

        logger.info("Attempting to read input file: %s", INPUT_DATA_FILE_PATH)
        try:
            BarcodeInput = parse_barcode_input(INPUT_DATA_FILE_PATH)
            logger.info("File read successfully:")
        except Exception as e:
            error_message ="Error while reading or processing input file"
            write_error_to_file(error_message)
            logger.error("Error while reading or processing the file: %s", e)
            raise

        logging.info("Attempting to read xml file: %s", xml_file_path)
        config = get_config_from_xml(xml_file_path)
        CERT_DER_PATH = config['cert_file_path']
        print("XML file settings:")
        print("CERT_DER_PATH:", CERT_DER_PATH)
        logging.info("der_File being used for certificate reference: %s", CERT_DER_PATH)

        cert_public_key = load_public_key_from_der(CERT_DER_PATH)
        print(cert_public_key)
        check_ecdsa_curve_p521(CERT_DER_PATH)

        identifier, flag, data = remove_prefix(BarcodeInput)

        logger.info("Barcode Input:%s", BarcodeInput)
        print("Barcode Identifier:", identifier)
        print("Barcode Flag:", flag)
        print("Identifier and flag removed", data)

        IsSigned, IsZipped = determine_signature_status(flag)
        print("Issigned:", IsSigned)
        print("IsZipped:", IsZipped)

        data = add_base32_padding(data)
        print("Base 32 padding added:", data)

        logger.info("Base 32 decoding...")
        data = base32_decode(data)
        print("Base 32 decoded", data.hex())
        if IsZipped:
            logger.info("IsZipped value true, Decompressing...")
            data = decompress_data(data)
            print("Decompressed:", data.hex())
            logger.info("Decompressed:  %s", data.hex())

        # Header
        Head_data = HeadReader(data, IsSigned)
        country_identifier = Head_data.get("Country Identifier")
        signature_algorithm = Head_data.get("Signature Algorithm")
        certificate_reference = Head_data.get("Certificate Reference")
        signature_creation_date = Head_data.get("Signature Creation Date")
        data = Head_data.get("Remaining Data")
        
        # Prenta í skipanalínu
        print("Country Identifier:", country_identifier.hex() if country_identifier else None)
        if signature_algorithm:
            print("Signature Algorithm:", signature_algorithm.hex())
        if signature_creation_date:
            print("Signature Creation Date:", signature_creation_date.hex())
        if certificate_reference:
            print("Certificate Reference:", certificate_reference.hex())
            logger.info("Certificate Reference (hex): %s", certificate_reference.hex())
            
        if data:
            print("Remaining Data:", data.hex())

        # MessageZone
        message_zone, data, der_tlv_message_zone = extract_message_zone(data)
        print("Message Zone:", message_zone.hex())
        print("Remaining Data:", data.hex())

        SignatureZoneCheck(data, IsSigned, logger)

        signer_certificate_data, data = ExtractSignerCertificateZone(data, IsSigned, logger)
        if signer_certificate_data:
            print("Signer Certificate Data:", signer_certificate_data.hex())
            logger.info(f"Signer Certificate Data:", signer_certificate_data.hex())

        # SignatureZone
        signature_zone = SignatureReader(data, IsSigned)
        if signature_zone:
            print("Signature:", signature_zone.hex())
            logger.info("Signature Zone: %s", signature_zone.hex())

        # Deep MessageZone
        extracted_message_data = MessageZoneReader(message_zone)

        print("")
        print("OUTPUTS ############:")
        print("")

        logger.info("Scanning messagezone...")
        decoded_message_data = decode_message_zone_data(extracted_message_data)

        for data_type in decoded_message_data.keys():
            logger.info(f"Data type found: {data_type}")

        extracted_message_data = MessageZoneReader(message_zone)
        decoded_message_data = decode_message_zone_data(extracted_message_data)

        if country_identifier:
            string_decoded_country_identifier = c40_decode(country_identifier)
            print("Country identifier:", string_decoded_country_identifier)
            logger.info(f"Decoded Country Identifier: {string_decoded_country_identifier}")
        if signature_creation_date:
            string_decoded_date = decode_date(signature_creation_date)
            print("Signature Date:", string_decoded_date)
            logger.info(f"Signed on: {string_decoded_date}")

        if "Card Access Number" in decoded_message_data:
            CAN = decoded_message_data["Card Access Number"]
            write_to_file(can=CAN, logger=logger)
            print("CAN: ", CAN)
            logging.info("Card access number written to output file.")
        elif "Machine Readable Zone (TD1)" in decoded_message_data:
            MRZ1, MRZ2, MRZ3 = MRZSplitter(decoded_message_data["Machine Readable Zone (TD1)"])
            Full_NAME = decoded_message_data.get("Full Name", "N/A")
            first_name = Full_NAME.split(' ')[0]
            print("FULL NAME:", Full_NAME)
            logger.info("First element of name: %s", first_name)

            write_to_file(mrz_data=(MRZ1, MRZ2, MRZ3), full_name=Full_NAME, logger=logger)
            print("MRZ: ", MRZ1, MRZ2, MRZ3)
            logging.info("MRZ and FN written to output file.")
        else:
            logger.error("No MRZ or CAN data extracted from the messagezone,  nothing written to output file.")

        if IsSigned == True:
            PossiblySignedData = country_identifier + signature_algorithm + certificate_reference + signature_creation_date + der_tlv_message_zone

            message_hex = PossiblySignedData.hex()
            signature_hex = signature_zone.hex()

            print("Comparing this message:", PossiblySignedData.hex())
            print("With this signature;", signature_hex)
            print("Using this certificate that ends with this thumbprint:", certificate_reference)

            print("der_tlv message zone", der_tlv_message_zone.hex())

            #dno the difference.  but this gets the public key from cert
            DER_CERT_PUBKEY = get_public_key_from_der_certificate_as_string(CERT_DER_PATH)
            print(DER_CERT_PUBKEY)

            # Convert the PEM public key string to a VerifyingKey object using SECP521r1
            vk = ecdsa.VerifyingKey.from_pem(DER_CERT_PUBKEY, hashfunc=sha512)  # Ensure the correct hash function is used if needed
            # samanborning
            try:
                is_valid = vk.verify(bytes.fromhex(signature_hex), bytes.fromhex(message_hex), hashfunc=sha512)  # Ensure the correct hash function is used
                if is_valid:
                    print("The signature is valid.")
                    logger.info("Signature is valid")
                else:
                    print("The signature verification failed.")
                    logger.info("The signature verification failed.")
            except ecdsa.BadSignatureError:
                print("The signature seems to be invalid. Please check that certificate reference for DecodeConfig.xml is correct, and the cert is the correct one.")
                logger.info("The signature seems to be invalid.  Please check that certificate reference for DecodeConfig.xml is correct, and the cert is the correct one.")
            

        print("Script end reached succesfully.")
        logging.info("Script end reached succesfully.")
    except Exception as e:
        error_message = f"An error occurred: {e}\n traceback: {traceback.format_exc()}"
        logger.error(error_message)

if __name__ == "__main__":
    main()
