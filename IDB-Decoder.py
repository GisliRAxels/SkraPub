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
