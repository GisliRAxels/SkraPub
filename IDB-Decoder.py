import base64
import zlib
import logging
from logging.handlers import RotatingFileHandler
import os
import traceback

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

def setup_logging():
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Log file path
    log_file = os.path.join(os.getcwd(), 'BarcodeDecoder.log')

    # Create a rotating file handler
    handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
    handler.setFormatter(log_formatter)

    # Create a logger and set its level
    logger = logging.getLogger('BarcodeDecoderLogger')
    logger.setLevel(logging.DEBUG)

    # Add the file handler to the logger
    logger.addHandler(handler)

    return logger

def determine_signature_status(flag):
    if flag in ['A', 'C']:
        IsSigned = False
    elif flag in ['B', 'D']:
        IsSigned = True
    else:
        raise ValueError("Invalid flag. Flag must be 'A', 'B', 'C', or 'D'.")
    
    return IsSigned

def parse_barcode_input(file_path):
    """
    Reads a text file and returns its contents as a string.

    :param file_path: Path to the text file containing the barcode input.
    :return: String read from the file.
    """
    with open(file_path, 'r') as file:
        return file.read().strip()
    
def c40_decode(encoded_bytes):
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
            if U == 0:  # Shift 1
                shift = 1
            elif U == 1:  # Shift 2
                shift = 2
            elif shift:
                # Apply shift offset and reset shift
                decoded_string += REVERSE_C40_CHART.get((U + (40 * shift)) % 40, "")
                shift = None
            else:
                decoded_string += REVERSE_C40_CHART.get(U, "")

    return decoded_string

def decompress_data(data):
    return zlib.decompress(data)

def base32_decode(encoded_bytes):
    """
    Decode the Base32 encoded bytes.
    
    Args:
    - encoded_bytes (bytes): The Base32 encoded bytes to decode.
    
    Returns:
    - bytes: The decoded bytes.
    """
    return base64.b32decode(encoded_bytes)

def add_base32_padding(encoded_string):
    """
    Add padding to a Base32 encoded string.

    Args:
    - encoded_string (str): The Base32 encoded string.

    Returns:
    - str: The padded Base32 encoded string.
    """
    padding_needed = (8 - len(encoded_string) % 8) % 8
    return encoded_string + '=' * padding_needed

def HeadReader(barcode_data, IsSigned):
    remaining_data = None

    if IsSigned == False:
        if len(barcode_data) < 2:
            raise ValueError("Barcode data is too short for this flag type.")
        country_identifier = barcode_data[:2]
        remaining_data = barcode_data[2:]

    elif IsSigned == True:
        if len(barcode_data) < 11:
            raise ValueError("Barcode data is too short for this flag type.")
        country_identifier = barcode_data[:2]
        signature_algorithm = barcode_data[2:3]
        signature_creation_date = barcode_data[3:6]
        certificate_reference = barcode_data[6:11]
        remaining_data = barcode_data[11:]

    else:
        raise ValueError(f"Invalid barcode flag: {IsSigned}")

    header_data = {
        "Country Identifier": country_identifier,
        "Signature Algorithm": signature_algorithm if IsSigned else None,
        "Signature Creation Date": signature_creation_date if IsSigned else None,
        "Certificate Reference": certificate_reference if IsSigned else None,
        "Remaining Data": remaining_data
    }

    return header_data

def extract_message_zone(data):
    if len(data) < 2:
        raise ValueError("Data is too short to contain a valid message zone.")

    # Check for the tag
    tag = data[0]
    if tag != 0x61:
        raise ValueError(f"Expected tag 0x61, but found {tag}.")

    # Extract the length
    length_byte = data[1]
    if length_byte & 0x80:  # Long form
        num_length_bytes = length_byte & 0x7F  # Number of subsequent bytes
        if num_length_bytes == 0 or num_length_bytes > len(data) - 2:
            raise ValueError("Invalid length bytes in DER-TLV encoding.")
        length = int.from_bytes(data[2:2 + num_length_bytes], 'big')
        start_index = 2 + num_length_bytes
    else:  # Short form
        length = length_byte
        start_index = 2

    # Ensure there's enough data for the message zone
    if start_index + length > len(data):
        raise ValueError("Data is truncated or length is incorrect.")

    # Extract the message zone
    message_zone = data[start_index:start_index + length]

    # Remaining data
    remaining_data = data[start_index + length:]

    return message_zone, remaining_data

def MessageZoneReader(message_zone):
    index = 0
    message_data = {}

    # Mapping of tag values to message types
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
        # Extract the tag
        tag = message_zone[index]
        index += 1

        # Extract the length
        length_byte = message_zone[index]                   
        index += 1

        if length_byte & 0x80:  # Long form
            num_length_bytes = length_byte & 0x7F
            length = int.from_bytes(message_zone[index:index + num_length_bytes], 'big')
            index += num_length_bytes
        else:  # Short form
            length = length_byte

        # Extract the value
        value = message_zone[index:index + length]
        index += length

        # Identify and store the data group
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
            # Decode using c40_decode
            decoded_value = c40_decode(value)
        elif tag == "Full Name":
            # Decode bytes directly to string
            decoded_value = value.decode('utf-8')
            

        elif tag == "MicroFace":
            # Save as jp2 image and keep raw value
            save_image_as_jp2(value, 'MicroFace.jp2')
            decoded_value = value
        else:
            # Undefined decoding, keep as is
            decoded_value = value

        decoded_data[tag] = decoded_value

    return decoded_data

def save_image_as_jp2(image_data, filename):
    directory_path = "C:\\PY\\BarcodeDecodeOutput"
    # Ensure the directory exists, create it if it doesn't
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)

    file_path = os.path.join(directory_path, filename)
    with open(file_path, 'wb') as file:
        file.write(image_data)
    print(f"Saved {file_path}")

def SignatureZoneCheck(data, IsSigned, logger):
    if IsSigned:
        if not data:
            logger.error("SignatureZoneCheck: No data found in the signature zone, but IsSigned is True.")
            raise ValueError("No data in signature zone despite IsSigned being True.")
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
        # If IsSigned is False, no processing is needed
        logger.info("IsSigned is False. Skipping Signer Certificate Zone processing.")
        return None, data

    if not data or data[0] != 0x7E:
        # If the first byte is not 0x7E, log and continue with the rest of the data
        #logger.info("0x7E tag not found in Signer Certificate Zone, Skipping.")
        return None, data

    # Handle DER-TLV encoding for Signer Certificate Data
    index = 1  # Start after the tag

    # Extract the length of the Signer Certificate Data
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

    # Ensure there's enough data for the Signer Certificate Zone
    if index + length > len(data):
        logger.error("Data is truncated or length is incorrect in Signer Certificate Zone.")
        return None, data

    # Extract the Signer Certificate Data
    signer_certificate_data = data[index:index + length]

    # Remaining data after Signer Certificate Zone
    remaining_data = data[index + length:]

    return signer_certificate_data, remaining_data

def SignatureReader(data, IsSigned):
    if IsSigned == False:
        if data:
            print("Warning: IsSigned is False but there is remaining data in Signature Zone.")
            print("Remaining Data:", data.hex())
        return None

    if len(data) < 2:
        raise ValueError("Data is too short to contain a valid signature zone.")

    # Check for the tag
    tag = data[0]
    if tag != 0x7F:
        raise ValueError(f"Expected tag 0x7F for signature zone, but found {tag}.")

    # Extract the length
    length_byte = data[1]
    if length_byte & 0x80:  # Long form
        num_length_bytes = length_byte & 0x7F  # Number of subsequent bytes
        if num_length_bytes == 0 or num_length_bytes > len(data) - 2:
            raise ValueError("Invalid length bytes in DER-TLV encoding.")
        length = int.from_bytes(data[2:2 + num_length_bytes], 'big')
        start_index = 2 + num_length_bytes
    else:  # Short form
        length = length_byte
        start_index = 2

    # Ensure there's enough data for the signature zone
    if start_index + length > len(data):
        raise ValueError("Data is truncated or length is incorrect.")

    # Extract the signature zone
    signature_zone = data[start_index:start_index + length]

    # Check for any remaining data
    remaining_data = data[start_index + length:]
    if remaining_data:
        print("Warning: Unclear data remaining after signature zone:", remaining_data.hex())

    return signature_zone

def MRZSplitter(mrz_data):
    """
    Splits the MRZ data into three parts, each 30 characters long.
    Raises an error if the MRZ data is not exactly 90 characters.

    :param mrz_data: The MRZ data string (expected to be 90 characters).
    :return: A tuple containing three parts of the MRZ data.
    """
    #
    if len(mrz_data) != 90:
        raise ValueError("MRZ data must be exactly 90 characters long.")
    
    return mrz_data[:30], mrz_data[30:60], mrz_data[60:]

def write_to_file(mrz_data=None, full_name=None, can=None, logger=None):
    directory_path = "C:\\PY\\BarcodeDecodeOutput"
    file_name = "BarcodeDecodeOutputData.txt"
    full_file_path = os.path.join(directory_path, file_name)

    # Ensure the directory exists, create it if it doesn't
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
    """
    Process the barcode string to extract the Barcode Identifier, Barcode Flag,
    and update the barcode data.

    Args:
    - barcode_string (str): The original barcode string.
    
    Returns:
    - tuple: A tuple containing the Barcode Identifier, Barcode Flag, and the updated barcode data.
    """
    if len(barcode_string) < 5:
        raise ValueError("Barcode string is too short to extract required information.")
    
    if not barcode_string.startswith("IDB"):
        raise ValueError("Prefix of barcode is wrong")
    
    barcode_identifier = barcode_string[:4]
    barcode_flag = barcode_string[4]
    updated_data = barcode_string[5:]

    return barcode_identifier, barcode_flag, updated_data

def decode_hex_to_string(hex_string):
    try:
        # Convert hex to bytes
        byte_data = bytes.fromhex(hex_string)

        # Decode bytes using UTF-8
        return byte_data.decode('utf-8')
    except ValueError as e:
        print(f"Error during decoding: {e}")
        return None

INPUT_DATA_FILE_PATH = r'C:\PY\BarcodeDecodeInput\BarcodeDecodeRawInput.txt'

def main():
    try:
        logger = setup_logging()  # Initialize logging

        logger.info("Attempting to read input file: %s", INPUT_DATA_FILE_PATH)
        try:
            BarcodeInput = parse_barcode_input(INPUT_DATA_FILE_PATH)
            logger.info("File read successfully: %s", BarcodeInput)
        except Exception as e:
            logger.error("Error while reading or processing the file: %s", e)
            raise  # Re-raise the exception to exit from main

        #For testing purposes only
        #BarcodeInput = 'IDB1APCOOXG4VZDDMTITAMGOASAAQOMBJC'
        #BarcodeInput = 'IDB1DPCOOXG6FHR67DSZT7SV3XVATTNMCZWLNPLWE776P4ZJ6AN36U2PCM5KIETKJOR6YYZGU74TPNC4GXOVUNDPSYYI3GB2L5OH2VDJ43GBNOKRMYDITJYO32XD7BAULVOUJ7EDAGAYDJ5LIBAQCF5LTWF4QFWJFMUSZSBKWBJAAMQZUA2K5ECOQDJGFGIZVFCUA6RYSBHWGYDEM4DSSYPAJ7HE7KPCAQZQKGIYDA5YDCUT77577D7EKACIWTMDNKAADVB6EM5SGY37UCDB4EATAGKYLBMB6H7YYAZQQOBYPR4AGJ5B7QVAZLAORXEUDLMJEGVCSDKKSYG7SANOPFPANKXNBFS22QOBTH5H4CSGPKTH6B7YEA2IB6GEYXGAOMTF657C4B3ZODO45K53GYS3STB7Z3ZSESRDOVPMMMXJJHRK3M3XHO72Q72T7KKHZ6SVKKVFX5KWB347ULFHR3V7PLJJZJF7HHOKXJMMPVPCMGW326OBA2O46HF5ORPS75Z4PUPTOMV3UEZHN5ZFYTOYTNK7BRR4AN46K5DWUO6RKHEZGJFYVDJYUZWX6XHZ7ZVBDH7TR4P5WIRVAC42ER76STYIHKFY5GRHGJSKRMPUU6TALRWHPU7G6FP7BDRDY6GNOCJ25W5ZM7TDY3WNWCL3LH6N7NS3OGYMJ433JXY2TGPS5THNNSL5464F4T3O7S33XGJP3DSJRHGLNLM2EWOHEW76Z6XXOXN6SYXJ6WZRID2PVP6NBVTVWRKC7YLZEHZ5TV2KDZ7Z6X57KP7SSP4J3DQWJZN7XXT2NLJX53HJQ4NX345U24ONOI6ISVK3IKL4LEMXVU3RSFN6B27G57X6KJH3W2YSTLZQPPIXVWXH33ZIZVGXQ232JXMGHAEI24POTYWXW33HV6HI7DHQ3WJQ3VVW5QB3TPDRG37HCYUHS64UF47JV7TX3JK7WPM7UOV46C7Z3JGF647ZXCE6WX4NLH6YEIO5V4WBGZJ7DZMNIIMS3QV5NKBV65FPNDGRDYFO7R2FZMGSFG3WNQV7TWNQKPWNRLGRFOEQ637LKS6LV5F55EH23BFBVM6IBV3MTH5V4HF26U44SY7FEHL5ZNNW5637WJY4HEZOVNLVYOWRJFWGW6IV73QKPRPB6PREWPSPKLE6LP72UJENDQ53SC2Y3JRYZPSNOJTDG6O7O7BX54YKD6LPV7EXKFZVXZRSEIZPWH2PLLE2FXHUOLF63Y4SNZJRMGHOVTKLTFVNS6PXFYYGO2T7PWVZU4GYZE52L4LZ53HH72PV6HP4SWR473D7JMHF764LY4JEY5BSURZNG77J7QOR3LSS2H2DFXSBRUK6LDTGTGS6NTFSDRF5M2NGT3X56JD64BH4CAPHKX7R3YQTW7O7W6DUL2HARYW5DOEZ3CMSI6766L7J6BP7OPUO5P6W6BETG2W7WXYLWMOQU5VWFAIZQXHXF6SEGF5D7A2T6XYKYSXOOLOK5ZQW4V5TE4WW2MH26VHO34NJGK2JG327CLPZDGOG2MLUWR3G3RPXP6IWI2HFJXRN24TY6JWW6FXM37E3GOILLZHRU643KUWH4S54FNS42XOMTMF5ERFGIZGQA73S7DWTLBK66X7NPR4OK7HC4OHS776VGUIZXNXUULMNNPP7M5SYQZNP6W6EDZPX4BF4G743VPSI6TYLRU5FY67YIJUBAQXB5HAQDCQHLPOL3AYC3WHE6DQJOEGKU57YNHTXPSSDBVZ3O75DW6H5YVXYVQEOM5R22B5KPKBSZIRTSWZ65355TKPNVLOHWXWGDWPHH6BJ27CNTH3WQ5Y4M3Z46VZEBU2CGT53UN55LS5ADABFDB5SE'
        #Error Test Data
        #BarcodeInput = 'IDB1DPCOOXG6FHR67DSZ7TNT3PZHG2YVRMW36TMJ77U7ZWT4A337II6U32UQJCC7D5QRWNZ5ZG72BYNO5DJ2G7FTQRWMBUN76D45UN3DUXWTLLATS76IDCWYVXGHPWAYDA4DEQUUCQ4DSWVZYCWJC5ESRKBOZAVDAUQBWAMKFNBOSDHAFULBTEMSQRSA7A5RGTDAMNTWKBNIMPRE7TOOFBRQKMIEDANZTOUDROJ77674BRSNGBMLJ2AGTAACK47SGOZD4D7CEBA7CGIYDFMFQWB7A7YMQOZYHA4EIYBDH6U4YKQMRQHIL2KJUWUSTCQJCVFL4BPJHGPEC3RORLSSSRMFLH43TSSGHJTHVBT7E7YAAPEAYDGML5BHGJ666RR6G5MUR3P6WORT4DNZJQ36NSZCOINUK5XOBLQWT4VVXN7SXP4QP5J7VPCU2JWVVMSTZV7D52PCBSX3N27PRUE7EW6LXXNIEUHH4XVHTPMFIHMQ5HP7GSOWY5Z774OHKNZ7EKZ3CMTGY4O4Z5MZRVTQI46YC6DG672SCPEVDYN3FSIIRY4SO3H53Z5H324TT5ZY6HSZEC2YEO5CYT6JP4EAVG5GWITSU5FQUHSIPBQF737W2FT7BXTTR6QMODKWRG564OQX73QMO3K3BH4NX7S7GXMPBM2HOH4434NKTDZO5TKVZP6GMO26ZTX77NJ3TCWNRZE3D3E6UWNDLHD2JPXPPH37KWXJ4HVXIMYXR7GKR7SR2R2DPVJNMH52422KZFZ6747L67VC75JXSEVRYPH4W735ZJHV23OYTM36M3V2OONOJGPCPILK3N4DFOSELS2NM2C27A5PXOPZ75GTZ25KJRX4IHXWLC3L345UUUYT32NH4E7WHAQMFNLHXL4LLDN5HY7DVXTTIM3EZV52DPYO5RWR4TNZSBKK7YPMLK5PQ37Z25WVP3X6P2GK6NRJ4FWT656D43WC7JLWG5U7MBUNOC6LITMY6JYWOWUAJ55KCVVM3PNSHVBZJJ7C3NY5CUVDZCDB363KPYLOYNB3GZF7ISWC4PNTUNNPFZ6U76TDFNQ4QKRPYA2XXRU6G6TU47KO6JMHT2BVO6W6366N3YEUPLVMLJW72UBLUWS7CTPES6NQFH6XQ4X6SLCZHWF6P5U7FJEQHZ2OZYRJN5RYQNHZHHGZNTPPPXNQ36OOFJ5FH3PULVH4S2MYZKGM33D3G5VSFAL337DS7OMIJW4UEWTDWK3VVZS6XRNH3SMKD7PJXV3M42JD4OCM555FE753TX6HO4TX7ZPICPN57EXD677MFEIECO6QZKO46R7RUX3HQ6VXIFF5RR3VAY3FTGRXSZVJHGJQZZ4SOW5KTZ63C6UR76CTODAHTVL7Q74OI3OXDYPL3FZDUJMPOZTCM6BOJ4OP7NVRV7GXXWX6GWW7HPA2I3OL3334ETEHUKOQ22QEE3L72C6J6DSQQXWNZ63SFMOLPGVZEW4Y7PK4YSKLHOWF5PLTPNOKULGNYTN3PZDXMSTNDVGF2KYRTV7XLWPKLEJDSV34X5OJUOUVLPD3GPP6MLDEFV47Y2KOVX2DD6NOSAWXONLXGJGA7CISHEM7JQP5VPBRI5WV7NLRWP26HG77RWHD5NPVK3PEUYW32KFWOXH566IZML4WWHLPOD4R36GS6D76MKWZYPZUFAYO64PJ4EA2URYHQWTQQDBOCNTXZ6QGBF6DSNBUEPED5IOX5WXZTXJFBY645X76R3IDW42R4K4CTG6Q5NH6BGVIZUSIZ23K7636OZVLWCWXX2LXDB7HDR7OUNLR22T52YM42E5U7HJ42CKDB3M65ZGS7F3OADKMH5LL'

        identifier, flag, data = remove_prefix(BarcodeInput)

        
        print("Barcode Identifier:", identifier)
        print("Barcode Flag:", flag)
        print("Identifier and flag removed", data)

        IsSigned = determine_signature_status(flag)
        print("Issigned", IsSigned)

        data = add_base32_padding(data)
        print("Base 32 padding added:", data)

        data = base32_decode(data)
        print("Base 32 decoded", data.hex())

        data = decompress_data(data)
        print("Decompressed:", data.hex())

        # Header
        Head_data = HeadReader(data, IsSigned)
        country_identifier = Head_data.get("Country Identifier")
        signature_algorithm = Head_data.get("Signature Algorithm")
        signature_creation_date = Head_data.get("Signature Creation Date")
        certificate_reference = Head_data.get("Certificate Reference")
        data = Head_data.get("Remaining Data")
        
        # Print the data
        print("Country Identifier:", country_identifier.hex() if country_identifier else None)
        if signature_algorithm:
            print("Signature Algorithm:", signature_algorithm.hex())
        if signature_creation_date:
            print("Signature Creation Date:", signature_creation_date.hex())
        if certificate_reference:
            print("Certificate Reference:", certificate_reference.hex())
        if data:
            print("Remaining Data:", data.hex())

        # MessageZone
        message_zone, data = extract_message_zone(data)
        print("Message Zone:", message_zone.hex())
        print("Remaining Data:", data.hex())

        #SignatureZoneCheck,  checks the remaining data,  weather there is remaining data in accordance with IsSigned, and if there is "signature Certificate Zone"
        SignatureZoneCheck(data, IsSigned, logger)

        #Signature Certificate Zone Exctraction
        signer_certificate_data, data = ExtractSignerCertificateZone(data, IsSigned, logger)
        if signer_certificate_data:
            print("Signer Certificate Data:", signer_certificate_data.hex())

        # SignatureZone
        signature_zone = SignatureReader(data, IsSigned)
        if signature_zone:
            print("Signature:", signature_zone.hex())

        # Deep MessageZone
        extracted_message_data = MessageZoneReader(message_zone)
        print("")
        print("OUTPUTS ############:")
        print("")
        for message_type, data in extracted_message_data.items():
            print(f"{message_type}: {data.hex()}")

        # Decode the MessageZone Contents
        decoded_message_data = decode_message_zone_data(extracted_message_data)

        # Print the decoded data
        for message_type, data in decoded_message_data.items():
            print(f"{message_type}: {data if isinstance(data, str) else data.hex()}")

        # Log the types of data found
        for data_type in decoded_message_data.keys():
            logger.info(f"Data type found: {data_type}")

        extracted_message_data = MessageZoneReader(message_zone)
        decoded_message_data = decode_message_zone_data(extracted_message_data)

        if "Machine Readable Zone (TD1)" in decoded_message_data:
            MRZ1, MRZ2, MRZ3 = MRZSplitter(decoded_message_data["Machine Readable Zone (TD1)"])
            Full_NAME = decoded_message_data.get("Full Name", "N/A")
            write_to_file(mrz_data=(MRZ1, MRZ2, MRZ3), full_name=Full_NAME, logger=logger)
        elif "Card Access Number" in decoded_message_data:
            CAN = decoded_message_data["Card Access Number"]
            write_to_file(can=CAN, logger=logger)
        else:
            logger.error("No MRZ or CAN data available.")
            
    except Exception as e:
        error_message = f"An error occurred: {e}\n traceback: {traceback.format_exc()}"
        logger.error(error_message)

        # Write the error details to err.txt in the user's home directory
        home_dir = os.path.expanduser('~')
        err_file_path = os.path.join(home_dir, 'err.txt')
        with open(err_file_path, 'w') as err_file:
            err_file.write(error_message)

if __name__ == "__main__":
    main()
