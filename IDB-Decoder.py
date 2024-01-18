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

def write_error_to_file(error_message, file_path='err.txt'):
    """Write the provided error message to the specified file."""
    try:
        with open(file_path, 'w') as file:
            file.write(error_message)
    except Exception as e:
        logging.error(f"Failed to write error to {file_path}: {e}")

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
        error_message ="Invalid flag. Flag must be 'A', 'B', 'C', or 'D"
        write_error_to_file(error_message)
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
    args:  bytes

    returns: string
    '''
    # Remove the date mask (first byte)
    relevant_data = encoded_date[1:]
    
    # Convert the bytes to an integer
    date_int = int.from_bytes(relevant_data, 'big')

    # Extract the year, month, and day
    year = date_int % 10000
    date_int //= 10000
    day = date_int % 100
    month = date_int // 100

    # Format the date as MMDDYYYY
    decoded_date = f"{month:02}{day:02}{year}"
    return decoded_date

def extract_message_zone(data):
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
    else:  # Short form
        length = length_byte
        start_index = 2

    # Ensure there's enough data for the message zone
    if start_index + length > len(data):
        error_message ="Not enough data in messagezone"
        write_error_to_file(error_message)
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
            error_message ="no data in signature zone found but issigned is true"
            write_error_to_file(error_message)
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
        error_message ="Signature zone data seems to be wrong"
        write_error_to_file(error_message)
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
        error_message ="Unclear data remaining after signature zone"
        write_error_to_file(error_message)
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
        error_message ="The mrz data needs to be 90 characters.."
        write_error_to_file(error_message)
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
        error_message ="Prefix of barcode is wrong."
        write_error_to_file(error_message)
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
            error_message ="Error while reading or processing input file"
            write_error_to_file(error_message)
            logger.error("Error while reading or processing the file: %s", e)
            raise  # Re-raise the exception to exit from main

        #For testing purposes only
        #BarcodeInput = 'IDB1APCOOXG4VZDDMTITAMGOASAAQOMBJC'
        #BarcodeInput = 'IDB1DPCOOXG6FZSUWZLNIYUQLQWZDWGE4LEW5U3D755H7NQ7AK7XDM7VGSUUHIRBH26MENXOPIJH7Q2DLXJSLRP3M2EVWAFB6PC5LR45N3DGZEIT4VXBQ4HKNDS7VQ6AKFK43TBXTAMBQ6BSAKKBI6BZLK4YB3ERGSJMVAVMQKRQKIA3AHFGWAXJBSQC2FQZSHJIIJAPQPYTJBSGOZ3BAGUGPZSPZHFCYYYFGEABQG4ZXKBY7E77776AQZGTAWFUVADJQQDFGOZDHMT6B7RGAANRDFMFSWAYDB7UPMEIHM4HQ6AEEARX7KMMFIGIYTWFVEE2LKJJRJERKCX6AWUXTXQBFZXIVZJJIXCRT6PZRJDHUJT2QZ7SPMAAPTAMBTEFWRTXE7NPAZ7HOWKIVW7LHIZ6JW4UY55GZMRHEW2FG3XEVYJJWL23WPZL77IH6E727RKNELK26JJY27T6VGRAZ37WVOX42SPSDPF33WWCKDT6LKRZ7XCQDGKOTW7XJXJMO4776HBVG47SFM7ROITMOXMMWXMY2Z2EGOMFPRTPH5JFHSIRUG5SZUEI4PJHNT4546TZ56JZ654LDJOSBMMCH6TMJ6ET6CAKTOTLEZZKGTYKDJEHYZC75P3NCZ7Q3ZZY7JGHBFJI3O7OHYJ75ZGDNFNQT7G77ZNTDWHUWNBXL6OJ6GVJZ5XOZFK476DGH5PMZ373WE7ZRLGY4SNRVSPKLGTV3R5EXLXX347RLLU6L23UG4LYXTFI7ZK5I5BX2EUWD65B65NFMT47P6PVXP2RP6U3RCK44XT6LP564UT25NXIJGP7OM25HHGXETHRHUFVFX6FSHDZKFZJGWPBNPQOX3XHU76TJM5OVEY76UD33FRNV54O2LKIJN5G36CL3DQIODWRTLX6NVRS6D4PR335ZEEN2M265BV4HPY3I6LW4YARFP6H6FVKXYP7U5O3KX73XG5HFPEYU7C7JPM7B6N3B7WVTDO2PGC2OXBLFULWMOE4LHJKIE66VBK26MXWZTYQ4UU7R5W4GRKKRMTBY47JVH4FXNGQ5TMSXUJPB6FWZ3GSXS67CP7NRSUYGJFIX4CND2Y6PTNJ2OPRHPGWDZ5E2XPLPN7LG56CCGV2WVW3H5KEV2LJPQJXSZNGYDT7LYOLXJFVMT3CXH62PSWSIC4ZHM4IUW644YGTUTTTMG3X7W3WYN5HPDU2ST7XSE2T6ZNGEMVDG57RVSO2ZSSFV47VZPVGME3OKCLJZ3FJ226ZPLYSTN3GNB7XULY56PNEROFBOP66SSP65Z37DXOJ364XURHWW7SPRPN76CSECRFPIMVDO7I7Y3L5TYNKTVCS6YY52RMNSZTITZM6UTREYM46JHLO5J47NRPKA77BJHDQLZ2V7IN6PFNTLB6H55SYRKGWHWM5RGNA7F6HH7U2Q37XL33LXDLPPTVQNFNTF555WDJSD2HHAMNICSPV75BLE7BZAJL7G45NZDWHFXRK4SLOM7VVONJFFDVLK7XVZHUXFLFTG4LWVX4R3GLJWR2TC5HMIZ273F3H5FSERZK56L6XE2HKCVXV5TFXXGFVSSY6P4NFHK35JQ7CXZCLLXGR3DGTIOREJTQGPVYH62VQQVO7K7WVY2H5PTRPXZ3HR6WX2UNTS2OLF4FG3XLT67PAMWH6LLDRXXD6A47DJ7B7XHFPM4F42CQMHPMHU6CANKI4DYLJYIDQXBG53M5ILBS7BZEQSDHSB6WGS3DASZ7V57ZX5TMU67IGIGLY5NOOCD5HTPNCHGS5FOCFMCU3Z6HWAMLK3XQMEYNGCYYRVI5ULKRHK3H2W2GILHHWHEL4WH3OH3XHMZWPO5I2X2NBBTNAZBV4OV5WMP6Y7F6MMTV7Q436JHERKQE76XP6ETCWT22H4FCIKZI73EIQV5UJSPLF62WPSXNEGIPR44FFOXK2K4Y3J557ZZ6S4HZB3L5766Y5AACDGCNJA'
        
        #Error Test Data
        #BarcodeInput = 'IDB1DPCOOXG6FHR67DSZ7TNT3PZHG2YVRMW36TMJ77U7ZWT4A337II6U32UQJCC7D5QRWNZ5ZG72BYNO5DJ2G7FTQRWMBUN76D45UN3DUXWTLLATS76IDCWYVXGHPWAYDA4DEQUUCQ4DSWVZYCWJC5ESRKBOZAVDAUQBWAMKFNBOSDHAFULBTEMSQRSA7A5RGTDAMNTWKBNIMPRE7TOOFBRQKMIEDANZTOUDROJ77674BRSNGBMLJ2AGTAACK47SGOZD4D7CEBA7CGIYDFMFQWB7A7YMQOZYHA4EIYBDH6U4YKQMRQHIL2KJUWUSTCQJCVFL4BPJHGPEC3RORLSSSRMFLH43TSSGHJTHVBT7E7YAAPEAYDGML5BHGJ666RR6G5MUR3P6WORT4DNZJQ36NSZCOINUK5XOBLQWT4VVXN7SXP4QP5J7VPCU2JWVVMSTZV7D52PCBSX3N27PRUE7EW6LXXNIEUHH4XVHTPMFIHMQ5HP7GSOWY5Z774OHKNZ7EKZ3CMTGY4O4Z5MZRVTQI46YC6DG672SCPEVDYN3FSIIRY4SO3H53Z5H324TT5ZY6HSZEC2YEO5CYT6JP4EAVG5GWITSU5FQUHSIPBQF737W2FT7BXTTR6QMODKWRG564OQX73QMO3K3BH4NX7S7GXMPBM2HOH4434NKTDZO5TKVZP6GMO26ZTX77NJ3TCWNRZE3D3E6UWNDLHD2JPXPPH37KWXJ4HVXIMYXR7GKR7SR2R2DPVJNMH52422KZFZ6747L67VC75JXSEVRYPH4W735ZJHV23OYTM36M3V2OONOJGPCPILK3N4DFOSELS2NM2C27A5PXOPZ75GTZ25KJRX4IHXWLC3L345UUUYT32NH4E7WHAQMFNLHXL4LLDN5HY7DVXTTIM3EZV52DPYO5RWR4TNZSBKK7YPMLK5PQ37Z25WVP3X6P2GK6NRJ4FWT656D43WC7JLWG5U7MBUNOC6LITMY6JYWOWUAJ55KCVVM3PNSHVBZJJ7C3NY5CUVDZCDB363KPYLOYNB3GZF7ISWC4PNTUNNPFZ6U76TDFNQ4QKRPYA2XXRU6G6TU47KO6JMHT2BVO6W6366N3YEUPLVMLJW72UBLUWS7CTPES6NQFH6XQ4X6SLCZHWF6P5U7FJEQHZ2OZYRJN5RYQNHZHHGZNTPPPXNQ36OOFJ5FH3PULVH4S2MYZKGM33D3G5VSFAL337DS7OMIJW4UEWTDWK3VVZS6XRNH3SMKD7PJXV3M42JD4OCM555FE753TX6HO4TX7ZPICPN57EXD677MFEIECO6QZKO46R7RUX3HQ6VXIFF5RR3VAY3FTGRXSZVJHGJQZZ4SOW5KTZ63C6UR76CTODAHTVL7Q74OI3OXDYPL3FZDUJMPOZTCM6BOJ4OP7NVRV7GXXWX6GWW7HPA2I3OL3334ETEHUKOQ22QEE3L72C6J6DSQQXWNZ63SFMOLPGVZEW4Y7PK4YSKLHOWF5PLTPNOKULGNYTN3PZDXMSTNDVGF2KYRTV7XLWPKLEJDSV34X5OJUOUVLPD3GPP6MLDEFV47Y2KOVX2DD6NOSAWXONLXGJGA7CISHEM7JQP5VPBRI5WV7NLRWP26HG77RWHD5NPVK3PEUYW32KFWOXH566IZML4WWHLPOD4R36GS6D76MKWZYPZUFAYO64PJ4EA2URYHQWTQQDBOCNTXZ6QGBF6DSNBUEPED5IOX5WXZTXJFBY645X76R3IDW42R4K4CTG6Q5NH6BGVIZUSIZ23K7636OZVLWCWXX2LXDB7HDR7OUNLR22T52YM42E5U7HJ42CKDB3M65ZGS7F3OADKMH5LL======='
        #BarcodeInput = 'IDB1DPCOADEAEN755TRID44BLVQUAACURSJYHHS25XUWBXAQY3I5JHS4DE5K4CM6BGPATHQJTYEZ4CM6BGPATKFDFOUTCFBONTRKMNUZPYVKXJOVCMKATHQJTYEZ4CM6BGPP6GGVYEA7IW6JALWBLIUSRKD7KBX6QAG7VK35XQ6YFNZAMQKVPRG3JRUNNY6VK77AIEPTOBHZ6IGU7AI4R2ZUHAW3SL3L7FFQKP4XJWLVGNPRKSYEGYT3XCJMVGJTDOP2CSZPHFGLGSDLXADUO6JDXTIJRKSLKJI2L35M47DH27MXX3N26C5BP4MXVHQ5QYY7REXHZXEICDVRBQSCHGTDAALRESTSX5GPDZJ4LDX6P4SS27KX7AKHHIR2C5TAKKCDKEH325OGEJ4ZFEDB745PI4BXW4KCOFC3BH7WMRTH32ZXMVXORUC2FHX5MCWJPMG2OOK4GYZOVOHIC7QZILKC2AVY5UGI4NTGAXXUYEWZDGECB5OIMCM67RDQJH5Y3LM3RNASVI6XIVU3A5OVVAEEOFMRJKI6OTKCIOLDQUNCDOGUSRORR7P6UJOYWUQG2RVRDCPHWGJBRCLCPX4PGXWHSAL4EPUZDLRW2RN7KTXCVGPDO2GHGVGEOJM7DRONIGAF2KULBL74KEEQX6T5XMPUZMTUPGVK442W5TN7C5TZH3FTJY6MAPDNC5LC2I55LGJTOUGWT2K7MYXNRFBV6DEJKL3TPQWP3ROETJS4L3EYZRNOBYEYZZQRQO2TJ2ZYZYQ6XQNOBK3NG2ZOZ3XSAJFXEND2F6SV3FB4IZXTS36JTYZ5JTGUI4YLHIRCVZCRT3IIB3X75ZSJKIDUCJK7ROGRU5YEIKO2AMNKFIFUP6ET7DG5DPNZEXGMCODHMPBILCNTR3M772OLZM6WGVELWZXMHVJVH4NWFDBJMESLSFDVP42WAEPM5MT4OZMRIPQAQF55Q4WCCADKW7UGSTKQDBRQBA5TAFG7UXUW7WGQZIRRLZPZ6VNHXUEJBOFJNMU4YB43Y5KO7EIPF3GB2IWCL5ZE336EUEHH5BH4ZB5DEYZANRBTPTZE2SPZTS6BN4KRJ5CYAVHJHOUTHIFDGZD2WR4WMIHOIS2QK5CBGZMQEFY5E4PO5GRXHETXK5EUTRGCHXYTMAHKG5TYHGEKLW4V7SJXMABKS6G3G2IOC7VLHELDPHU5O4KVPP5YFCPRFRFAOFTKGQMZ6PXD27WEKOM5ENWVCXDJ5HMIKIFAKYS3JCHO6MIXP4PNIXP6YLPCPRMPE4DM53M7ITOI3HWYPVD5DNFS7MJJVNQZ5V5TTRKQENDOFYEQNTFZXUN3P7LYE3HFCK3SXHFJMBHTVOD2T3PYJKEKUDNJT5WRPJW7N35LXEGSXWFFKG56XXVF6F46TBMGXLU3C3FYW3ATGJJJ74K6IQVQGS4IFG3GFIZJL7MUXJWOQVZ2XE7VXM7IUW4PGOVZRYFR56LB76TA6PBQNGPDFNNS6CQHPCFB5JOLE4RPFVG2KQ2QBRMGKHBYSYR4IOVJ24YBMDDY4C4AQOSSXL7KKCJXTGBBO5BN4XDAUKDIRPIPH3LA57IEPQT5BIOBAOOXDU4ONHJRCQJNHVWCXZDQMFITGTIN4FQOEFQCSVA63HDPF4YN4JOYMKPUCNAUMV6IMXH4G5JY37ERW4J327MRDHPPSKDNXNAS7XUW3HF3IFOJWSKUFZIWDOHMG4A6UE3LKQFW7VTN7EN34VILEPQ5NONWGSICSMFTW4YLSEBAXQZLMONZW63T7IC73ESPHCF6EIRX5HJLJG4RVSEZNB34MDYPJZR7I2BNK54WTS7JBR7CRLYLOS5E3WSCLN5XXUE6JLTLY7FMUC5XVQJOPF3OWBYPD5AHBNNLD7HA'
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
        certificate_reference = Head_data.get("Certificate Reference")
        signature_creation_date = Head_data.get("Signature Creation Date")
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

        # Decode the MessageZone Contents
        decoded_message_data = decode_message_zone_data(extracted_message_data)

        # Log the types of data found
        for data_type in decoded_message_data.keys():
            logger.info(f"Data type found: {data_type}")

        extracted_message_data = MessageZoneReader(message_zone)
        decoded_message_data = decode_message_zone_data(extracted_message_data)

        # If we are decoding small barcode
        if "Card Access Number" in decoded_message_data:
            CAN = decoded_message_data["Card Access Number"]
            write_to_file(can=CAN, logger=logger)

        #If we are decoding big barcode
        elif "Machine Readable Zone (TD1)" in decoded_message_data:
            MRZ1, MRZ2, MRZ3 = MRZSplitter(decoded_message_data["Machine Readable Zone (TD1)"])
            Full_NAME = decoded_message_data.get("Full Name", "N/A")
            write_to_file(mrz_data=(MRZ1, MRZ2, MRZ3), full_name=Full_NAME, logger=logger)
        
        #IF Something wrong with the data
        else:
            logger.error("No MRZ or CAN data available.")

        # Add condition to print specific data
        print(f"Machine Readable Zone (TD1): {MRZ1} {MRZ2} {MRZ3}")
        print(f"MicroFace: {decoded_message_data.get('MicroFace')}")
        print(f"Full Name: {Full_NAME}")

        if signature_creation_date:
            string_decoded_date = decode_date(signature_creation_date)
            logger.info(f"string_decoded_date MMDDYYYY: {string_decoded_date}")

        if country_identifier:
            string_decoded_country_identifier = c40_decode(country_identifier)
            print("Country identifier:", string_decoded_country_identifier)
            logging.info("Decoded Country Identifier: ", string_decoded_country_identifier)

    except Exception as e:
        error_message = f"An error occurred: {e}\n traceback: {traceback.format_exc()}"
        logger.error(error_message)

if __name__ == "__main__":
    main()

    #d9c503e702bac28000a91927073cb5dbd2c1b8218da3a93cb832755c
