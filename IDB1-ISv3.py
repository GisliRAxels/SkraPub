from datetime import datetime
from logging.handlers import RotatingFileHandler
from PIL import Image

import xml.etree.ElementTree as ET
import os
import zlib
import base64
import hashlib
import logging
import qrcode
import traceback
import sys
import time
import PyKCS11


#Paths,  modify to your needs.

#A .jp2 image that is of max 1200 bytes in size (very small)
MF_IMAGE_PATH = 'Path\To\Your\Image\MicroFace.jp2'

'''
An input .txt file which includes data for barcode in the following format:

[MRZ line 1]
[MRZ line 2]
[MRZ line 3]
[CAN]
[FULL_NAME]
[normal / test / specimen] - (0, 1 or 2)
'''
INPUT_DATA_FILE_PATH = r'Path\To\Your\BarcodeInput\barcode_input_data.txt'


"""
constants specific to the to your needs.

please note that the flag will not produce any meaningful effects regarding the processing methods.
Currently the payload for the barcode on back is ZLIB + base 32 encoded and the front barcode is not zlib encoded.
"""

#Constants
BARCODE_IDENTIFIER = "IDB1"
BARCODE_FLAG = "D"
FRONT_BARCODE_FLAG = "A"
ISSUING_COUNTRY = "ISL".encode('utf-8')
SIGNATURE_ALGORITHM = bytes([0x03])
BIG_BARCODE_PREFIX = BARCODE_IDENTIFIER + BARCODE_FLAG
FRONT_BARCODE_PREFIX = BARCODE_IDENTIFIER + FRONT_BARCODE_FLAG


def write_error_to_file(error_message, file_path='err.txt'):
    """
    args:
        A text string

    For logging errors.
    Writes the provided error message to the specified file.
    """
    try:
        with open(file_path, 'w') as file:
            file.write(error_message)
    except Exception as e:
        logging.error(f"Failed to write error to {file_path}: {e}")

def parse_text_file(file_path):
    """
    args:
        Path to a txt file in the following format;
        [MRZ1]
        [MRZ2]
        [MRZ3]
        [CAN]
        [FULL_NAME]
        [normal / test / specimen]
    returns
        Those specific values as strings.

    Parsing in text file which incude personalization information for the barcode generation, 
    This is specific to the production system
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()

        if len(lines) < 6:
            raise ValueError("File format is incorrect or missing data.")

        # Extracting data
        MRZ = ''.join(line.strip() for line in lines[0:3]) 
        CAN = lines[3].strip()
        FULL_NAME = lines[4].strip()
        TYPE_CODE = lines[5].strip()

        # Validate and convert TYPE_CODE
        #0 = Normal,  1 = Specimen,  2 = Test
        if TYPE_CODE not in ['0', '1', '2']:
            error_message = f"Document type(normal/specimen/test) not in barcode input text file: {e}\n{traceback.format_exc()}"
            logging.error(error_message)
            write_error_to_file(error_message)
            raise ValueError("Type of document not specified in input text file")
            write_error_to_file(error_message)
        if TYPE_CODE == '0':
            TYPE = 'NORMAL'
        elif TYPE_CODE == '1':
            TYPE = 'SPECIMEN'
        elif TYPE_CODE == '2':
            TYPE = 'TEST'
        else:
            raise ValueError("Invalid document type code.")
        
        return MRZ, CAN, FULL_NAME, TYPE
    except Exception as e:
        error_message = f"Error processing file {file_path}: {e}\n{traceback.format_exc()}"
        logging.error(error_message)
        write_error_to_file(error_message)  # Write the specific error to err.txt
        raise

#Function to read xml file
def get_config_from_xml(file_path):
    config = {}

    # Parse the XML file
    tree = ET.parse(file_path)
    root = tree.getroot()

    # Iterate over each child of the root element and add to config dictionary
    for child in root:
        if child.tag == 'slot_number':
            # Convert slot_number to int
            config[child.tag] = int(child.text)
        else:
            config[child.tag] = child.text

    return config

"""
Values defined for the C40 encoding., based on the description of the
ICAO standardized document 9303 Part 13,  chapter 2.6
"""
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
#Obsolete as of now,  useful for decoding C40
REVERSE_C40_CHART = {value: key for key, value in C40_CHART.items()}

def ensure_all_bytes(*args):
    """
    Args:
        Some byte data.
    Returns
        Nothing

    Verifying data as bytes.  A.K.A byte-check,  raises error if not bytes.
    """
    for i, item in enumerate(args, start=1):
        if not isinstance(item, bytes):
            error_message = f"Item {i} is not bytes. It's of type {type(item)}."
            logging.error(error_message)
            write_error_to_file(error_message)  #write to err.txt if byte check fails.
            raise TypeError(error_message)  
        else:
            good_message = f"Item {i} passes byte check before signing."
            logging.info(good_message)

def create_barcode_raw_file(content, directory=r"C:\PY\BarcodeOutput"):
    """
    Args:
        
    Returns
    Creation of txt file that includes the pure barcode output for further processing, specific to the production environment.
    """
    try: 
        # Ensure the directory exists
        if not os.path.exists(directory):
            os.makedirs(directory)

        # Constructing the filename
        filename = f"Barcode_raw.txt"
        file_path = os.path.join(directory, filename)

        # Writing content to the file
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(content)
        logging.info("Back Barcode raw file created %s", file_path)

    except Exception as e:
        error_message = f"Error creating barcode raw file: {e}\n{traceback.format_exc()}"
        logging.error(error_message)
        write_error_to_file(error_message)  # Optionally write to err.txt
        raise

def create_front_barcode_raw_file(content, directory=r"C:\PY\BarcodeOutput"):
    """
    Args:
        A string
    Returns
        Nothing, but creates txt file.

    This function creates the front barcode (CAN) raw data in txt.
    """
    try:
        # Ensure the directory exists
        if not os.path.exists(directory):
            os.makedirs(directory)

        # Constructing the filename
        filename = f"Front_Barcode_raw.txt"
        file_path = os.path.join(directory, filename)

        # Writing content to the file
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(content)
    except Exception as e:
         error_message = f"Error creating front barcode raw file: {e}\n{traceback.format_exc()}"
         logging.error(error_message)
         write_error_to_file(error_message)

    logging.info("Front Barcode file created %s", file_path)

def read_image_to_bytes(image_path):
    """
    Args:
        String,  a path.
    Returns:
        byte data
    
    Reading in the image data for barcode.
    Note: the image specified for this code is at or under 1kb.
    """
    try:
        # Open the file in binary mode and read its contents
        with open(image_path, 'rb') as file:
            data = file.read()
            return data

    except FileNotFoundError:
        error_message = "Micro Image not found!!"
        print("### IMAGE NOT FOUND!!! ###")
        logging.error("FATAL ERROR!  Image not found %s", image_path)
        write_error_to_file(error_message)
        #return b'\x99' * 30  # Return 10 bytes of 0x99 (For testing without image.)
    except Exception as e:
        error_message = "Error occured while opening the input image"
        print(f"### AN ERROR OCCURED WHILE OPENING INPUT IMAGE!!!: ### {e}")
        logging.error("FATAL ERROR! Error occured while opening input image: %s", image_path)
        write_error_to_file(error_message)
        #return b'\x99' * 30  # Return 10 bytes of 0x99 (For testing without image.)

def delete_barcode_images():
    # Define the paths to the files
    files = [
        "C:\\PY\\BarcodeOutput\\Barcode_img.png",
        "C:\\PY\\BarcodeOutput\\Front_Barcode_img.png"
    ]
    
    # Loop through each file path
    for file_path in files:
        # Check if the file exists
        if os.path.exists(file_path):
            # If it exists, delete the file
            os.remove(file_path)
            print(f"Deleted: {file_path}")
            logging.info("deleted back barcode succesfully")
        else:
            # If the file does not exist, just continue
            print(f"File does not exist, skipped: {file_path}")
            logging.info("Barcode img didnt exist,  skipped")

def generate_qr_code(data, intended_size_in_cm=2.5, output_directory=r"C:\PY\BarcodeOutput"):

    '''

    Args:
        Byte data
    Return:
        Filename of newly created file of barcode.

    The actual specifications and the generations of the barcode.  
    
    Before changing the config specification settings for the barcode please look into the QR standard

    The QR code standard is specified by Denso Wave, Inc.  
    Referred document includes information on barcode data capacity.
    https://www.qrcode.com/en/about/version.html

    Please note that the intended_size_in_cm is for the calculation of the DPI only,
    the actual printing itself should be determined by layout and printing settings after
    running this script.
    '''

    qr = qrcode.QRCode(
        version=32,  #This determines the detail level of the barcode. Choose in accordance with data size of the barcode.
        error_correction=qrcode.constants.ERROR_CORRECT_M, #Increases Scannability, Durability and Data size Capability. L = 7%, M = 15%, Q = 25%, H = 30%
        box_size=1,  # How many pixels each "box" of the QR code is.
        border=2 #How many "boxes" the thickness of the border of the QRcode Image is.
    )

    # Add data
    qr.add_data(data)
    qr.make(fit=True)

    # Construct filename
    filename = f"Barcode_img.png"
    logging.info("Back Barcode Image Created %s", filename)

    try:
        # Ensure the output directory exists
        if not os.path.exists(output_directory):
            os.makedirs(output_directory)
    except Exception as e:
        error_message = "Error creating output directory for Barcode, Please make it yourself if error persists; C:\PY\BarcodeOutput "
        logging.error(f"Error creating directory {output_directory}: {e}")
        write_error_to_file(error_message)
    
    # Full path for saving the file
    full_path = os.path.join(output_directory, filename)

    # Create the QR code image
    img = qr.make_image(fill='black', back_color='white')

    try:
        img.save(full_path)
    except Exception as e:
        error_message ="Error saving QR Image in output path"
        logging.error(f"Error saving QR code image to {full_path}: {e}")
        write_error_to_file(error_message)

    # Calculate QR code dimensions for reference
    qr_version = qr.version
    modules_on_side = 4 * qr_version + 17
    logging.info("Squared Dimensions: %s", modules_on_side)

    # Calculate total number of dots/modules in the QR code
    total_dots = modules_on_side ** 2
    logging.info("Total Dots/Modules in QR Code %s", total_dots)

    # DPI Calculation based on intended print size in centimeters,  This might be wrong.
    intended_size_in_inches = intended_size_in_cm / 2.54  # Convert cm to inches
    dpi = (modules_on_side * qr.box_size) / intended_size_in_inches
    logging.info("Calculated DPI: %s", dpi)

    return filename

def generate_front_qr_code(data, intended_size_in_cm=0.7, output_directory=r"C:\PY\BarcodeOutput"):
    """

    Args:
        Byte data
    Returns:
        Filename of generated front qr code.
    
    The actual specifications and the generations of the FRONT(small) barcode.  
    
    Before changing the config specification settings for the barcode please look into the QR standard

    The QR code standard is specified by Denso Wave, Inc.  
    Referred document includes information on barcode data capacity.
    https://www.qrcode.com/en/about/version.html

    Please note that the intended_size_in_cm is for the calculation of the DPI only,
    the actual printing itself should be determined by layout and printing settings after
    running this script.
    """
    qr = qrcode.QRCode(
        version=3,  # This determines the detail level of the barcode. Choose in accordance with data size of the barcode.
        error_correction=qrcode.constants.ERROR_CORRECT_M, #Increases Scannability, Durability and Data size. L = 7%, M = 15%, Q = 25%, H = 30%
        box_size=1,  # How many pixels each "box" of the QR code is.
        border=1 #How many boxes the thickness of the border of the QRcode Image is.
    )

    # Add data
    qr.add_data(data)
    qr.make(fit=True)

    # Print the QR Code version
    print(f"QR Code Version: {qr.version}")

    # Construct filename using request_number
    filename = f"Front_Barcode_img.png"

    # Ensure the output directory exists
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    # Full path for saving the file
    full_path = os.path.join(output_directory, filename)

    # Create the QR code image
    img = qr.make_image(fill='black', back_color='white')

    try:
        img.save(full_path)
    except Exception as e:
        error_message = "Error saving front qr image"
        logging.error(f"Error saving QR code image to {full_path}: {e}")
        write_error_to_file(error_message)

    # Calculate QR code dimensions for reference
    qr_version = qr.version
    modules_on_side = 4 * qr_version + 17
    logging.info("front qr Squared Dimensions: %s", modules_on_side)

    # Calculate total number of dots/modules in the QR code
    total_dots = modules_on_side ** 2
    logging.info("Total Dots/Modules in front QR Code %s", total_dots)

    # DPI Calculation based on intended print size in centimeters
    intended_size_in_inches = intended_size_in_cm / 2.54  # Convert cm to inches
    dpi = (modules_on_side * qr.box_size) / intended_size_in_inches
    logging.info("Calculated DPI for front: %s", dpi)
    return filename

def ReplaceLessThanSymbol(data):
    """

    Args:
        
    Function is used for the MRZ data.  as per IDB the '<' symbol is replaced with a spacebar
    """
    if isinstance(data, str):
        return data.replace('<', ' ')
    elif isinstance(data, bytes):
        return data.replace(b'<', b' ')
    else:
        raise TypeError("Input must be of type str or bytes.")
    
def encode_date(date_obj=None):
    """
    Encodes the date using the specified format.
    
    Args:
    - date_obj: datetime.datetime object. If not provided, uses the current date.

    Returns:
    - bytes: Encoded date as per the given specification.
    """

    # If no date_obj is provided, use the current date
    if date_obj is None:
        date_obj = datetime.now()
        logging.info("No date provided.  using datetime.now")

    month = date_obj.month
    day = date_obj.day
    year = date_obj.year

    # Convert each date component to its string representation (or '00' if unknown)
    month_str = f"{month:02}" if month else '00'
    day_str = f"{day:02}" if day else '00'
    year_str = f"{year:04}" if year else '0000'

    # Compute the date mask
    mask = 0
    mask |= (0b10000000 if not month else 0)
    mask |= (0b01000000 if not month else 0)
    mask |= (0b00100000 if not day else 0)
    mask |= (0b00010000 if not day else 0)
    mask |= (0b00001000 if not year or len(year_str) < 1 else 0)
    mask |= (0b00000100 if not year or len(year_str) < 2 else 0)
    mask |= (0b00000010 if not year or len(year_str) < 3 else 0)
    mask |= (0b00000001 if not year or len(year_str) < 4 else 0)

    # Convert the concatenated string date to an integer and then to bytes
    date_int = int(month_str + day_str + year_str)
    logging.info("converting conc string date to int...: %s", date_int)
    date_bytes = date_int.to_bytes(3, byteorder='big')
    logging.info("converted to date bytes...: %s", date_bytes)

    # Combine the mask byte and the date bytes
    encoded_date = bytes([mask]) + date_bytes

    return encoded_date

def DER_encode_length(length):
    """Encode the length in DER format."""
    if length < 0x80:
        return bytes([length])
    else:
        encoded_length = int.to_bytes(length, byteorder='big', length=(length.bit_length() + 7) // 8)
        return bytes([0x80 | len(encoded_length)]) + encoded_length

def TLV_Encode_tagvalue(tag, value):
    """Encode the given tag and value in TLV format."""
    return tag + DER_encode_length(len(value)) + value

def TLV_encode_data(data_type, data_input):
    """Encode data based on its type."""
    tags = {
        "SIGNATURE": b'\x7F',
        "MRZ": b'\x07',
        "CAN": b'\x09',
        "TINYIMAGE": b'\xAB',
        "FULL_NAME": b'\xAA',
        "MSG_ZONE": b'\x61'
    }
    
    if data_type not in tags:
        raise ValueError(f"Unsupported data type: {data_type}")
    
    return TLV_Encode_tagvalue(tags[data_type], data_input)

def parse_DER_TLV(byte_data):
    index = 0
    parsed_data = {}
    tags = {
        b'\x61': "MSG_ZONE:",
        b'\x07': "MRZ",
        b'\x09': "CAN",
        b'\x7F': "SIGNATURE",
        b'\xAA': "FULL_NAME",
        b'\xAB': "TINYIMAGE",
        # Add other tags as needed
    }

    while index < len(byte_data):
        # Extract the tag
        tag = byte_data[index:index+1]
        index += 1
        
        if tag not in tags:
            # Skip if tag is not recognized and continue
            continue

        # Extract the length
        length_byte = byte_data[index]
        index += 1
        
        if length_byte & 0x80:  # Long form
            num_of_length_bytes = length_byte & 0x7F  # Number of subsequent bytes to represent length
            if num_of_length_bytes > 0:
                length = int.from_bytes(byte_data[index:index + num_of_length_bytes], 'big')
                index += num_of_length_bytes
            else:
                # Indefinite length is not supported here; adjust if needed
                raise ValueError("Indefinite lengths are not supported.")
        else:  # Short form
            length = length_byte

        # Ensure there's enough data left
        if index + length > len(byte_data):
            raise ValueError("Data is truncated or length is incorrect.")
        
        # Extract the value
        value = byte_data[index:index+length]
        index += length
        
        # Assign the extracted value to the corresponding tag
        parsed_data[tags[tag]] = value

    return parsed_data

def c40_encode(data):
    """
    C40 encoding method, based on the description of the
    ICAO standardized document 9303 Part 13,  chapter 2.6
    """
    if isinstance(data, bytes):
        data = data.decode('utf-8')

    encoded_bytes = []
    while data:
        segment = data[:3]
        data = data[3:]

        # C40 values
        U1 = C40_CHART.get(segment[0], 0)
        U2 = C40_CHART.get(segment[1], 0) if len(segment) > 1 else 0
        U3 = C40_CHART.get(segment[2], 0) if len(segment) > 2 else 0

        # padding (space)
        if len(segment) == 2:
            U3 = 0  # Shift
        elif len(segment) == 1:
            encoded_bytes.append(254)
            encoded_bytes.append(ord(segment[0]) + 1)
            continue  # 

        # Calculate U
        U = (1600 * U1) + (40 * U2) + U3 + 1

        # Split U into 2 bytes
        encoded_bytes.append(U // 256)
        encoded_bytes.append(U % 256)

    return bytes(encoded_bytes)

def ascii_to_binary(input_data):
    """
    Used for the custom Base-32 Encoding function which is obsolete
    since python already has many supportive libraries.  
    However i've decided to include this in case it ever changes.
    """

    if isinstance(input_data, str):  # If input is a string
        return ''.join(format(ord(char), '08b') for char in input_data)
    elif isinstance(input_data, bytes):  # If input is bytes
        return ''.join(format(byte, '08b') for byte in input_data)
    else:
        raise ValueError("Unsupported input type. Expected str or bytes.")

def zlib_compress(data: bytes) -> bytes:
    """Compress Bytes using ZLIB level 9."""
    return zlib.compress(data, level=9)

def custom_base32_encode(text, output_as_bytes=False):
    """
    Obsolete since python already have supportive libraries
    But i've decided to include this function in case it ever changes or is needed.
    """

    # Base-32 symbol chart
    symbols = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    
    # Convert to binary and pad to a group of 5 bytes
    binary_data = ascii_to_binary(text)
    while len(binary_data) % 40 != 0:
        binary_data += 'x'
    
    # Divide into 8 chunks of 5 bits
    chunks = [binary_data[i:i + 5] for i in range(0, len(binary_data), 5)]
    
    # Replace x's with 0's in chunks that have both actual bits and x's
    for i, chunk in enumerate(chunks):
        if 'x' in chunk and '0' in chunk or '1' in chunk:
            chunks[i] = chunk.replace('x', '0')
    
    # Convert to decimal or '='
    encoded_values = []
    for chunk in chunks:
        if 'x' in chunk:
            encoded_values.append('=')
        else:
            encoded_values.append(int(chunk, 2))
    
    # Map to Base-32 chart
    encoded_str = ''.join([symbols[val] if val != '=' else val for val in encoded_values])
    
    if output_as_bytes:
        return encoded_str.encode("utf-8")
    else:
        return encoded_str

def base32_encode(input_bytes):
    """
    Encode the input bytes using Base32.
    
    Args:
    - input_bytes (bytes): The input bytes to encode.
    
    Returns:
    - bytes: The Base32 encoded bytes.
    """
    return base64.b32encode(input_bytes)

def remove_base32_padding(encoded_data: bytes) -> bytes:
    """
    Remove padding from a Base32 encoded byte sequence
    as specified by the IDB standard
    """
    return encoded_data.rstrip(b'=')

def get_certificate_reference(der_file_path):
    """
    Generate the Certificate Reference from a DER encoded certificate file.

    Args:
    - der_file_path (str): File path to the DER encoded certificate.

    Returns:
    - str: last 5 bytes of the hash of The Certificate Reference.

    Reads in the .der certificate and computes the last 5 hash of the Certificate Reference
    as specified by the IDB 3.2.3 Certificate Reference 
    This field has to be present for signed barcodes.

    """
    try:
        # Read the DER encoded certificate file
        with open(der_file_path, 'rb') as file:
            der_data = file.read()

        # Compute SHA1 hash of the certificate
        sha1_hash = hashlib.sha1(der_data).digest()

        # Extract the last 5 bytes of the hash
        certificate_reference = sha1_hash[-5:]

        return certificate_reference

    except FileNotFoundError:
        print(f"File not found: {der_file_path}")
        error_message = "DER certificate reference file not found."
        logging.error(f"DER certificate reference file not found in {der_file_path}: {e}")
        write_error_to_file(error_message)
        return None
    
    except Exception as e:
        print(f"An error occurred: {e}")
        error_message = "An error unknown error occured while computing the DER certificate reference"
        logging.error("An error unknown error occured while computing the DER certificate reference")
        write_error_to_file(error_message)
        return None

def GetPin():

    '''
    Needs to be implemented to your needs.
    '''

    pin = 'x'

    return pin

def LunaSign(data_to_sign, slot_number, key_label, pin):
    """
    Args:
    - Data to be signed

    Returns:
    - Signed data.

    Signs the barcode through an API.
    The specific cryptoki.dll API used needs to support the signing mechanism along with the equipment being used.

    Needs to be tailored to your specific needs, label, slot, mechanism need to be specified.
    
    """
    signature_bytes = b'x1'

    return signature_bytes

def main_pipeline(input):
    """ 
    Function for putting payload through ZLIB and base32.
    """
    
    # Step 1: ZLIB Compression

    print("before zlib size in bytes:", len(input))
    payload_zlib_compressed = zlib_compress(input)
    print("After zlib size in bytes:", len(payload_zlib_compressed))

    #Step 2: Base32 Encoding
    Base32EncodedPayload= base32_encode(payload_zlib_compressed) # When using ZLIB compressed data
    print("After Base32 length in bytes", len(Base32EncodedPayload))

    return Base32EncodedPayload

def main():
    """
    Main function.  
    
    Run as a try exception to gracefully exit if something goes wrong and logging purposes.
    """
    try:
        logging.info("")
        logging.info("###### Beginning of script instance ######")
        logging.info("")
        delete_barcode_images()
        time.sleep(2)
        logging.info("Attempting to read input file: %s", INPUT_DATA_FILE_PATH)

        XML_FILE_PATHS = {
            'NORMAL': 'C:\\PY\\NormalBarcodeConfig.xml',
            'SPECIMEN': 'C:\\PY\\SpecimenBarcodeConfig.xml',
            'TEST': 'C:\\PY\\TestBarcodeConfig.xml',
        }

        #Get data from raw txt file.
        try:
            MRZ, CAN, FULL_NAME, TYPE = parse_text_file(INPUT_DATA_FILE_PATH)  # Now includes TYPE
            logging.info("File read successfully. Data extracted: MRZ: %s, CAN: %s, Full Name: %s, Type: %s", 
                        MRZ, CAN, FULL_NAME, TYPE)
            
            # Determine the XML file path based on the TYPE
            xml_file_path = XML_FILE_PATHS.get(TYPE)
            if xml_file_path:
                logging.info("Using XML configuration: %s", xml_file_path)
            else:
                raise ValueError("Invalid document type for XML configuration")
                
        except Exception as e:
            error_message = "Error while reading or processing text file"
            logging.error("Error while reading or processing the file: %s", e)
            write_error_to_file(error_message)
        
        #read the barcode config
        logging.info("Attempting to read xml file: %s", xml_file_path)
        config = get_config_from_xml(xml_file_path)
        der_file_path = config['cert_file_path']
        slot_number = config['slot_number']
        key_label = config['key_label']
        print("XML file settings:")
        print("der_file_path:", der_file_path)
        print("slot_number:", slot_number)
        logging.info("der_File being used for certificate reference: %s", der_file_path)

        CERTIFICATE_REFERENCE = get_certificate_reference(der_file_path)
        CR_Length_in_bytes = len(CERTIFICATE_REFERENCE)
        print("cr byte length:", CR_Length_in_bytes)
        logging.info("Length of of certificate reference (bytes): %s", CR_Length_in_bytes)
        logging.info("Last 5 bytes of SHA1 of certificate reference (bytes): %s", CERTIFICATE_REFERENCE)
        logging.info("Last 5 bytes of SHA1 of certificate reference (hex): %s", CERTIFICATE_REFERENCE.hex())
        SIGNATURE_DATE = datetime.now()
        
        # Message Zone data
        TINYIMAGE = read_image_to_bytes(MF_IMAGE_PATH)
        logging.info("Tiny Image as bytes: %s", TINYIMAGE)
        logging.info("Tiny Image as hex: %s", TINYIMAGE.hex())
        MRZ = MRZ.encode('utf-8') #convert mrz to bytes 
        FULL_NAME = FULL_NAME.encode('utf-8') #Convert full name to bytes
        CAN = CAN.encode('utf-8') #Convert CAN to bytes

        #Get and encode date
        logging.info("Encoding date; %s", SIGNATURE_DATE)
        SIGNATURE_DATE = encode_date(SIGNATURE_DATE)
        SD_Length_in_bytes = len(SIGNATURE_DATE)
        logging.info("length of date byte: %s", SD_Length_in_bytes)
        logging.info("Encoded date in hex format: %s", SIGNATURE_DATE.hex())

        #ISSUING COUNTRY c40 encode.
        logging.info("Encoding Country code %s", ISSUING_COUNTRY)
        C40_ISSUING_COUNTRY = c40_encode(ISSUING_COUNTRY)
        logging.info("Encoded Country code in byte format: %s", C40_ISSUING_COUNTRY)
        logging.info("Encoded Country code in hex format: %s", C40_ISSUING_COUNTRY.hex())

        #MRZ,  replace spacebar and then C40 encode.
        logging.info("Replacing < in MRZ: %s", MRZ)
        EncodedMRZ = ReplaceLessThanSymbol(MRZ)
        logging.info("Replaced < in MRZ %s", EncodedMRZ)
        C40_MRZ = c40_encode(EncodedMRZ)
        hex_representation_C40_MRZ = ''.join([f'{byte:02x}' for byte in C40_MRZ])
        logging.info("Encoded MRZ: %s", hex_representation_C40_MRZ)

        #Card Access number
        C40_CAN = c40_encode(CAN)
        logging.info("C40 Encoded CAN: %s", C40_CAN.hex())

        #Print out total result of initial encodements.
        logging.info("Full Name (hexed): %s", FULL_NAME.hex())
        logging.info("Signature Algorithm to be used bytes: %s", SIGNATURE_ALGORITHM)
        logging.info("Signature Algorithm to be used: %s", SIGNATURE_ALGORITHM.hex())

        #CHECK TO SEE IF ALL PAYLOAD IS IN BYTES
        HeaderAndMsg = C40_ISSUING_COUNTRY + SIGNATURE_ALGORITHM + CERTIFICATE_REFERENCE + SIGNATURE_DATE + C40_MRZ + FULL_NAME + TINYIMAGE
        if isinstance(HeaderAndMsg, bytes):
            hex_representation = ''.join([f'{byte:02x}' for byte in HeaderAndMsg])
            logging.info("Payload passed Byte check,  Header and Messagezone in Hex, before DER-TLV %s", HeaderAndMsg.hex())
        else:
            error_message ="Payload data did NOT pass byte check."
            logging.error(" ERROR! Payload data did NOT pass Byte check!")
            write_error_to_file(error_message)

        
        #Apply DER-TLV on relevant data...
        data_items = {
            "MRZ": C40_MRZ,          # Use the encoded MRZ
            "TINYIMAGE": TINYIMAGE,
            #"SIGNATURE": SIGNATURE,
            "FULL_NAME": FULL_NAME,
            "CAN": C40_CAN
        }

        logging.info("Applying DER-TLV encodement on contents...")
        encoded_results = {key: TLV_encode_data(key, value) for key, value in data_items.items()}
        logging.info("DER-TLV MRZ: %s", encoded_results["MRZ"].hex())
        logging.info("DER-TLV MicroFace: %s", encoded_results["TINYIMAGE"].hex())
        logging.info("DER-TLV FULL_NAME: %s", encoded_results["FULL_NAME"].hex())

        #Apply DER-TLV on content of messagezone
        C40_TLV_MSGZONE = encoded_results["MRZ"] + encoded_results["FULL_NAME"] + encoded_results["TINYIMAGE"]
        
        #logging.info("DER TLV applied to contents of message zone: %s", C40_TLV_MSGZONE.hex())
        logging.info("DER TLV applied to contents of message zone")

        #Apply DER-TLV on messagezone...
        logging.info("Applying DER_TLV to back barcode message zone itself...")
        DER_TLV_ENCODED_MSGZONE = TLV_encode_data("MSG_ZONE", C40_TLV_MSGZONE)
        print("DER_TLV_ENCODED_MSGZONE:", DER_TLV_ENCODED_MSGZONE)
        logging.info("DER_TLV_ENCODED_MSGZONE in Hex: %s", DER_TLV_ENCODED_MSGZONE.hex())

        ########################################   Signature Zone   ########################################
        """
        As specified by the IDB, 3.5 on Signature Zone

        The input of the signature algorithm MUST be the (hash of the) concatenation of the header and the complete message zone, 
        ;  in our case the equipment the hashing is part of the signing process so no specific method is needed before passing in the data.

        The concatenated data is  
        C40_ISSUING_COUNTRY + SIGNATURE_ALGORITHM + CERTIFICATE_REFERENCE + SIGNATURE_DATE +  DER_TLV_ENCODED_MSGZONE(completely processed messagezone)
        """

        #Byte check before passing the data for signing.
        ensure_all_bytes(C40_ISSUING_COUNTRY, SIGNATURE_ALGORITHM, CERTIFICATE_REFERENCE, SIGNATURE_DATE, DER_TLV_ENCODED_MSGZONE)

        #data to be signed;  concatenation of the processed header and messagezone
        SIGNATURE = C40_ISSUING_COUNTRY + SIGNATURE_ALGORITHM + CERTIFICATE_REFERENCE + SIGNATURE_DATE + DER_TLV_ENCODED_MSGZONE


        pin = GetPin()


        #Send the data to be signed.
        logging.info("SIGNATURE before passing it to LunaSign: %s", SIGNATURE)
        logging.info("SIGNATURE before passing it to LunaSign in hex: %s", SIGNATURE.hex())
        logging.info("Key label used: %s", key_label)
        logging.info("Slot number being used: %s", slot_number)
        SIGNATURE = LunaSign(SIGNATURE, slot_number, key_label, pin) #Comment this out if signing is not readily available.


        logging.info("SIGNATURE returned from LunaSign (bytes): %s", SIGNATURE)
        if SIGNATURE is None:
            print("Error:  Returned Signature is None")
            logging.error("Error:  Signature is none")
            write_error_to_file("Error:  Returned Signature from Luna is None, check barcode_log for more details")
        logging.info("signed SIGNATURE data IN HEX: %s", SIGNATURE.hex())

        #Applying tag value and length denotion using DER-TLV onto the signature
        TLVSIGNATURE = TLV_encode_data("SIGNATURE", SIGNATURE)
        logging.info("DER-TLV applied on Signature zone:  %s", TLVSIGNATURE.hex())

        PAYLOAD = C40_ISSUING_COUNTRY + SIGNATURE_ALGORITHM + CERTIFICATE_REFERENCE + SIGNATURE_DATE + DER_TLV_ENCODED_MSGZONE + TLVSIGNATURE

        #logging.info("Payload before pipeline: %s", PAYLOAD.hex())

        #Main pipeline ( ZLIB and base32)
        logging.info("putting payload through main pipeline...")
        final_encodement = main_pipeline(PAYLOAD)
        #logging.info("Final payload Encodement: %s", final_encodement)
        logging.info("Payload succesfully zlib and base32 encoded.")
        final_encodement_nopadding = remove_base32_padding(final_encodement)
        final_encodement_string = final_encodement_nopadding.decode('utf-8')


        final_barcode_string = BIG_BARCODE_PREFIX + final_encodement_string
        logging.info("Generating Big QRCode from the processed data...")
        try:
            generate_qr_code(final_barcode_string)
            logging.info("Success Generating Big(Back) QRcode: %s", final_barcode_string)
        except ValueError as e:
            logging.error(e)

        logging.info("Generating Back Barcode raw txt file...")
        try:
            create_barcode_raw_file(final_barcode_string)
            logging.info("Success generating raw file")
        except ValueError as e:
            logging.error(e)

        logging.info("# Front Barcode Section #")
        C40_CAN = c40_encode(CAN)
        logging.info("C40 Encoded CAN: %s", C40_CAN.hex())
        logging.info("DER-TLV Encoded C40 Encoded CAN: %s", encoded_results["CAN"].hex())

        #Define content of front barcode messagezone
        C40_TLV_FRONT_MSGZONE = encoded_results["CAN"]

        #DERTLV on the messagezone.
        DER_TLV_ENCODED_FRONT_MSGZONE = TLV_encode_data("MSG_ZONE", C40_TLV_FRONT_MSGZONE) #??
        logging.info("DER TLV ENCODED Front Messagezone in Hex: %s", DER_TLV_ENCODED_FRONT_MSGZONE.hex())

        #print out and define the payload of front barcode.
        FRONT_PAYLOAD = C40_ISSUING_COUNTRY + DER_TLV_ENCODED_FRONT_MSGZONE
        logging.info("Front barcode payload: %s", FRONT_PAYLOAD.hex())

        #Main pipeline FRONT
        front_final_encodement = base32_encode(FRONT_PAYLOAD)
        print("After Base32 length in bytes", len(front_final_encodement))
        front_final_encodement_nopadding = remove_base32_padding(front_final_encodement)
        front_final_encodement_string = front_final_encodement_nopadding.decode('utf-8')
        front_final_barcode_string = FRONT_BARCODE_PREFIX + front_final_encodement_string
        logging.info(front_final_barcode_string)

        try:
            generate_front_qr_code(front_final_barcode_string)
            logging.info("Success generating Front(small) barcode.")
        except ValueError as e:
            print("Error:", e)
            logging.error(e)

        logging.info("Generating front small barcode raw txt file...")
        try:
            create_front_barcode_raw_file(front_final_barcode_string)
            print("Success generating raw txt file")
            logging.info("raw txt for small front barcode generated")
        except ValueError as e:
            print("Error:", e)
            logging.error(e)

        print("Script completed successfully.")

    except Exception as e:
        error_message = f"An unexpected error occurred: {e}\n{traceback.format_exc()}"
        logging.error(error_message)
        print("An error occurred. Please check the log file for details.")
    
    finally:
        print("Script finished. Exiting...")

if __name__ == "__main__":
    # Configure logging with rotating file handler
    handlers = [
        RotatingFileHandler("Barcode_log.log", maxBytes=10*1024*1024, backupCount=5),
        logging.StreamHandler()
    ]

    logging.basicConfig(level=logging.DEBUG, 
                        format='%(asctime)s %(levelname)s: %(message)s', 
                        datefmt='%Y-%m-%d %H:%M:%S',
                        handlers=handlers)

    sys.exit(main())
