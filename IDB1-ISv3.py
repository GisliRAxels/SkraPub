import os
import zlib
import base64
from datetime import datetime
import hashlib
import subprocess
import time
import random
import logging
from logging.handlers import RotatingFileHandler
import qrcode
import string
from PIL import Image
import io
import traceback
import sys

# Constants
MF_IMAGE_PATH = 'C:\\PY\\BarcodeInput\\MicroFace.jp2'
INPUT_DATA_FILE_PATH = r'C:\PY\BarcodeInput\barcode_input_data.txt'
BARCODE_IDENTIFIER = "IDB1"
BARCODE_FLAG = "D"
FRONT_BARCODE_FLAG = "A"
BIG_BARCODE_PREFIX = BARCODE_IDENTIFIER + BARCODE_FLAG
FRONT_BARCODE_PREFIX = BARCODE_IDENTIFIER + FRONT_BARCODE_FLAG
ISSUING_COUNTRY = "ISL".encode('utf-8')
SIGNATURE_ALGORITHM = bytes([0x03])
soosy = os.environ.get("sossy")

# Global variables
CERTIFICATE_REFERENCE = b'\x97\xa3\xe9\xcc\x0f' # random 5 bytes
SIGNATURE = b'\xf9>N\xca(&\t\xbbO\xe2\xed\xe0F\xacH\xa8S\x03J\xc0\x85\xfcRyZ(ck?~\xf7\xcd\x95\x87$\n\xbe\xe9^\xc3\x9c\xc3\xe5J\x91\x9a\xf2\xbbV\t[\xb9\xca\xc9\xc0\x82`\x96\xde-\xd9JD\x8b'


def write_error_to_file(error_message, file_path='err.txt'):
    """Write the provided error message to the specified file."""
    try:
        with open(file_path, 'w') as file:
            file.write(error_message)
    except Exception as e:
        logging.error(f"Failed to write error to {file_path}: {e}")


def parse_text_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()

        if len(lines) < 4:
            raise ValueError("File format is incorrect or missing data.")

        # Extracting data
        MRZ = ''.join(line.strip() for line in lines[0:3])  # MRZ lines are now 0, 1, 2
        CAN = lines[3].strip()  # CAN is now line 3
        FULL_NAME = lines[4].strip()  # FULL_NAME is now line 4

        return MRZ, CAN, FULL_NAME
    except Exception as e:
        #logging.error("Error processing file %s: %s\n%s", file_path, e, traceback.format_exc())
        #raise

        error_message = f"Error processing file {file_path}: {e}\n{traceback.format_exc()}"
        logging.error(error_message)
        write_error_to_file(error_message)  # Write the specific error to err.txt
        raise

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

def create_barcode_raw_file(content, directory=r"C:\PY\BarcodeOutput"):
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
        #return b'\x99' * 30  # Return 10 bytes of 0x99
    except Exception as e:
        error_message = "Error occured while opening the input image"
        print(f"### AN ERROR OCCURED WHILE OPENING INPUT IMAGE!!!: ### {e}")
        logging.error("FATAL ERROR! Error occured while opening input image: %s", image_path)
        write_error_to_file(error_message)
        #return b'\x99' * 30  # Return 10 bytes of 0x99
    
def get_certificate_reference(certificate_bytes):
    """
    Derive the Certificate Reference from the given certificate bytes.
    
    Args:
    - certificate_bytes (bytes): The DER-encoded certificate in bytes.
    
    Returns:
    - str: The Certificate Reference.
    """
    sha1_hash = hashlib.sha1(certificate_bytes).digest()
    # Get the last 5 bytes
    certificate_reference = sha1_hash[-5:]
    return certificate_reference.hex()  # Return as a hex string

def generate_qr_code(data, intended_size_in_cm=2.5, output_directory=r"C:\PY\BarcodeOutput"):

    #The QR code standard is trademarked by Denso Wave, Inc.  
    #Referred document includes information on barcode sizes.
    #https://www.qrcode.com/en/about/version.html

    qr = qrcode.QRCode(
        version=31,  #
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=1,  # decreased box_size for a smaller image
        border=2
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

    # DPI Calculation based on intended print size in centimeters
    intended_size_in_inches = intended_size_in_cm / 2.54  # Convert cm to inches
    dpi = (modules_on_side * qr.box_size) / intended_size_in_inches
    #print(f"DPI (if printed in {intended_size_in_cm}x{intended_size_in_cm} cm): {dpi}")
    logging.info("Calculated DPI: %s", dpi)

    return filename

def generate_front_qr_code(data, intended_size_in_cm=0.7, output_directory=r"C:\PY\BarcodeOutput"):
    qr = qrcode.QRCode(
        version=None,  # let the library decide the size
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=2,  # decreased box_size for a smaller image
        border=4
    )

    # Add data
    qr.add_data(data)
    qr.make(fit=True)

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
    #print(f"DPI (if printed in {intended_size_in_cm}x{intended_size_in_cm} cm): {dpi}")
    logging.info("Calculated DPI for front: %s", dpi)
    return filename

def ReplaceLessThanSymbol(data):
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
    date_bytes = date_int.to_bytes(3, byteorder='big')

    # Combine the mask byte and the date bytes
    #encoded_date = bytes([mask]) + date_bytes
    encoded_date = date_bytes

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
        "MICRO_FACE": b'\xAB',
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
        b'\xAB': "MICRO_FACE",
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
        # Check if the length is multi-byte
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
    # Convert bytes to string if necessary
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
    if isinstance(input_data, str):  # If input is a string
        return ''.join(format(ord(char), '08b') for char in input_data)
    elif isinstance(input_data, bytes):  # If input is bytes
        return ''.join(format(byte, '08b') for byte in input_data)
    else:
        raise ValueError("Unsupported input type. Expected str or bytes.")

def zlib_compress(data: bytes) -> bytes:
    """Compress Bytes using ZLIB."""
    return zlib.compress(data)

def custom_base32_encode(text, output_as_bytes=False):
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
    """Remove padding from a Base32 encoded byte sequence."""
    return encoded_data.rstrip(b'=')

def main_pipeline(input):

    # Step 1: ZLIB Compression
    payload_zlib_compressed = zlib_compress(input)
    #Step 2: Base32 Encoding
    Base32EncodedPayload= base32_encode(payload_zlib_compressed) # When using ZLIB compressed data

    return Base32EncodedPayload

def main():
    try:
        logging.info("")
        logging.info("###### Beginning of script instance ######")
        logging.info("")

        SIGNATURE_DATE = datetime.now()
        logging.info("Attempting to read input file: %s", INPUT_DATA_FILE_PATH)
        try:
            MRZ, CAN, FULL_NAME = parse_text_file(INPUT_DATA_FILE_PATH)
            logging.info("File read successfully. Data extracted: MRZ: %s, CAN: %s, Full Name: %s", 
                        MRZ, CAN, FULL_NAME)
        except Exception as e:
            error_message = "Error while reading or processing text file"
            logging.error("Error while reading or processing the file: %s", e)
            write_error_to_file(error_message)
        
        MICRO_FACE = read_image_to_bytes(MF_IMAGE_PATH)
        
        # Message Zone
        MRZ = MRZ.encode('utf-8') #convert mrz to bytes 
        FULL_NAME = FULL_NAME.encode('utf-8') #Convert full name to bytes
        CAN = CAN.encode('utf-8') #Convert CAN to bytes

        #Apply initial encodements on relevant sections of the barcode...
        #ENCODE DATE
        logging.info("Encoding date; %s", SIGNATURE_DATE)
        SIGNATURE_DATE = encode_date(SIGNATURE_DATE)
        logging.info("Encoded date in hex format: %s", SIGNATURE_DATE.hex())

        #ISSUING COUNTRY c40 encode.
        logging.info("Encoding Country code %s", ISSUING_COUNTRY)
        C40_ISSUING_COUNTRY = c40_encode(ISSUING_COUNTRY)
        logging.info("Encoded Country code in hex format: %s", C40_ISSUING_COUNTRY.hex())

        #MRZ,  replace spacebar and then C40 encode.
        logging.info("Replacing < in MRZ: %s", MRZ)
        EncodedMRZ = ReplaceLessThanSymbol(MRZ)
        logging.info("replacing < in MRZ %s", EncodedMRZ)
        C40_MRZ = c40_encode(EncodedMRZ)
        hex_representation_C40_MRZ = ''.join([f'{byte:02x}' for byte in C40_MRZ])
        logging.info("Encoded MRZ: %s", hex_representation_C40_MRZ)

        #CAN
        C40_CAN = c40_encode(CAN)
        logging.info("C40 Encoded CAN: %s", C40_CAN.hex())

        #Print out total result of initial encodements.
        logging.info("Full Name (hexed): %s", FULL_NAME.hex())
        logging.info("Signature Algorithm to be used: %s", SIGNATURE_ALGORITHM.hex())

        HeaderAndMsg = C40_ISSUING_COUNTRY + SIGNATURE_ALGORITHM + CERTIFICATE_REFERENCE + SIGNATURE_DATE + C40_MRZ + FULL_NAME + MICRO_FACE

        #CHECK TO SEE IF ALL PAYLOAD IS IN BYTES
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
            "MICRO_FACE": MICRO_FACE,
            #"SIGNATURE": SIGNATURE,
            "FULL_NAME": FULL_NAME,
            "CAN": C40_CAN
        }

        logging.info("Applying DER-TLV encodement on contents...")
        encoded_results = {key: TLV_encode_data(key, value) for key, value in data_items.items()}
        logging.info("DER-TLV MRZ: %s", encoded_results["MRZ"].hex())
        logging.info("DER-TLV MicroFace: %s", encoded_results["MICRO_FACE"].hex())
        logging.info("DER-TLV FULL_NAME: %s", encoded_results["FULL_NAME"].hex())

        #Apply DER-TLV on content of messagezone
        C40_TLV_MSGZONE = encoded_results["MRZ"] + encoded_results["MICRO_FACE"] + encoded_results["FULL_NAME"]
        logging.info("DER TLV applied to contents of message zone: %s", C40_TLV_MSGZONE.hex())

        #Apply DER-TLV on messagezone...
        logging.info("Applying DER_TLV to back barcode message zone itself...")
        DER_TLV_ENCODED_MSGZONE = TLV_encode_data("MSG_ZONE", C40_TLV_MSGZONE)
        logging.info("DER_TLV_ENCODED_MSGZONE in Hex: %s", DER_TLV_ENCODED_MSGZONE.hex())

        ########################################
        #Signature should be generated here.
        # Signature Zone
        #SIGNATURE = os.urandom(64)  # Random 64 bytes
        #SIGNATURE = C40_ISSUING_COUNTRY + SIGNATURE_ALGORITHM + CERTIFICATE_REFERENCE + SIGNATURE_DATE + DER_TLV_ENCODED_MSGZONE
        SIGNATURE = b'\xf9>N\xca(&\t\xbbO\xe2\xed\xe0F\xacH\xa8S\x03J\xc0\x85\xfcRyZ(ck?~\xf7\xcd\x95\x87$\n\xbe\xe9^\xc3\x9c\xc3\xe5J\x91\x9a\xf2\xbbV\t[\xb9\xca\xc9\xc0\x82`\x96\xde-\xd9JD\x8b'
        ##########################################
        logging.info("SIGNATURE IN HEX: %s", SIGNATURE.hex())
        TLVSIGNATURE = TLV_encode_data("SIGNATURE", SIGNATURE)

        #encoded_signature = TLV_encode_data("SIGNATURE", SIGNATURE)
        #signature_hex_str = "..."  # Your signature in hex string

        #SIGNATURE = encoded_results["SIGNATURE"]
        logging.info("DER-TLV applied on Signature zone:  %s", TLVSIGNATURE.hex())

        #SIGNATURE = C40_ISSUING_COUNTRY + SIGNATURE_ALGORITHM + CERTIFICATE_REFERENCE + SIGNATURE_DATE + DER_TLV_ENCODED_MSGZONE
        PAYLOAD = C40_ISSUING_COUNTRY + SIGNATURE_ALGORITHM + CERTIFICATE_REFERENCE + SIGNATURE_DATE + DER_TLV_ENCODED_MSGZONE + TLVSIGNATURE

        logging.info("Payload before pipeline: %s", PAYLOAD.hex())

        #Main pipeline
        logging.info("putting payload through main pipeline...")
        final_encodement = main_pipeline(PAYLOAD)
        logging.info("Final payload Encodement: %s", final_encodement)
        final_encodement_nopadding = remove_base32_padding(final_encodement)
        final_encodement_string = final_encodement_nopadding.decode('utf-8')

        final_barcode_string = BIG_BARCODE_PREFIX + final_encodement_string
        logging.info("Generating Big QRCode...")
        try:
            generate_qr_code(final_barcode_string)
            logging.info("Generated Big Barcode: %s", final_barcode_string)
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
        DER_TLV_ENCODED_FRONT_MSGZONE = TLV_encode_data("MSG_ZONE", C40_TLV_FRONT_MSGZONE) #????????? er þetta málið
        logging.info("DER TLV ENCODED Front Messagezone in Hex: %s", DER_TLV_ENCODED_FRONT_MSGZONE.hex())

        #print out and define the payload of front barcode.
        FRONT_PAYLOAD = C40_ISSUING_COUNTRY + DER_TLV_ENCODED_FRONT_MSGZONE
        logging.info("Front barcode payload: %s", FRONT_PAYLOAD.hex())

        #Main pipeline FRONT
        front_final_encodement = main_pipeline(FRONT_PAYLOAD)
        front_final_encodement_nopadding = remove_base32_padding(front_final_encodement)
        front_final_encodement_string = front_final_encodement_nopadding.decode('utf-8')

        front_final_barcode_string = FRONT_BARCODE_PREFIX + front_final_encodement_string

        logging.info(front_final_barcode_string)

        try:
            generate_front_qr_code(front_final_barcode_string)
            logging.info("Success generating barcode picture")
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
