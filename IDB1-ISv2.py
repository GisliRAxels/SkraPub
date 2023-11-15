import os
import zlib
import base64
from datetime import datetime

#barcode libraries
import qrcode
import random
import string
from PIL import Image

#get time now.
SIGNATURE_DATE = datetime.now()

# Constants

# Identifier + flag
BARCODE_IDENTIFIER = "IDB1"  # Just an example, replace with your value
BARCODE_FLAG = "D"      # Just an example, replace with your value
BARCODE_FRONT = BARCODE_IDENTIFIER + BARCODE_FLAG

# Header
ISSUING_COUNTRY = "ISL".encode('utf-8')
SIGNATURE_ALGORITHM = bytes([0x03]) # 
CERTIFICATE_REFERENCE = b'\x97\xa3\xe9\xcc\x0f' # random 5 bytes - GET cert ref here

# Message Zone
MRZ = 'P<UTOSPECIMEN<<PETER<<<<<<<<<<<<<<<<<<<<<<<<K7629352E7UTO8504279M2805203<<<<<<<<<<<<<<00'.encode('utf-8')
MINI_FACIAL = os.urandom(1000)  # Actual Implementation depends,  get from outside.
FULL_NAME = "Gísli Ragnar Axelsson".encode('utf-8')

# Signature Zone
#Todo,  put in actual signature.
SIGNATURE = b'\xf9>N\xca(&\t\xbbO\xe2\xed\xe0F\xacH\xa8S\x03J\xc0\x85\xfcRyZ(ck?~\xf7\xcd\x95\x87$\n\xbe\xe9^\xc3\x9c\xc3\xe5J\x91\x9a\xf2\xbbV\t[\xb9\xca\xc9\xc0\x82`\x96\xde-\xd9JD\x8b'

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


def generate_qr_code(data, filename="IDBQRCode.png", intended_size_in_cm=2.5):
    qr = qrcode.QRCode(
        version=None,  # let the library decide the size
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=2,  # decreased box_size for a smaller image
        border=4
    )

    # Add data
    qr.add_data(data)
    qr.make(fit=True)

    # Create the QR code image
    img = qr.make_image(fill='black', back_color='white')
    img.save(filename)

    # Calculate QR code dimensions for reference
    qr_version = qr.version
    modules_on_side = 4 * qr_version + 17
    print(f"QR Code Version: {qr_version}")
    print(f"Dimensions: {modules_on_side} x {modules_on_side} modules")

    # Calculate total number of dots/modules in the QR code
    total_dots = modules_on_side ** 2
    print(f"Total Dots/Modules in QR Code: {total_dots}")

    # DPI Calculation based on intended print size in centimeters
    intended_size_in_inches = intended_size_in_cm / 2.54  # Convert cm to inches
    dpi = (modules_on_side * qr.box_size) / intended_size_in_inches
    print(f"DPI (if printed in {intended_size_in_cm}x{intended_size_in_cm} cm): {dpi}")
    return filename

def ReplaceLessThanSymbol(data):
    if isinstance(data, str):
        return data.replace('<', ' ')
    elif isinstance(data, bytes):
        return data.replace(b'<', b' ')
    else:
        raise TypeError("Input must be of type str or bytes.")
    
#For now datamask is not included and commented out within this function.
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

    #FOR NOW THIS IS COMMENTED OUT.  AND DATA MASK IS NOT INCLUDED
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
        "MINI_FACIAL": b'\xAB',
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
        b'\x7F': "SIGNATURE",
        b'\xAA': "FULL_NAME",
        b'\xAB': "MINI_FACIAL",
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

def decompress_data(data):
    return zlib.decompress(data)

#Not used but decided to include it anyway,  seems 
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
    print("Zlib compressing...")
    payload_zlib_compressed = zlib_compress(input)
    print("zlib compression succesfull:")
    print(payload_zlib_compressed.hex())


    #Step 2: Base32 Encoding
    print("BASE32 encoding...")
    Base32EncodedPayload= base32_encode(payload_zlib_compressed) # When using ZLIB compressed data
    print("BASE32 encoding succesful....")

    return Base32EncodedPayload

# Combining the values to create the RAW PAYLOAD

#ENCODE DATE
print("Encoding date;", SIGNATURE_DATE, "...")
SIGNATURE_DATE = encode_date(SIGNATURE_DATE)
print("Encoded date in byte format: ", SIGNATURE_DATE)
print("Encoded date in hex format: ", SIGNATURE_DATE.hex())

#PRINT THE RAW PAYLOAD FOR CLARITY.
print ("RAW PAYLOAD")
print(ISSUING_COUNTRY + SIGNATURE_ALGORITHM + CERTIFICATE_REFERENCE + SIGNATURE_DATE + MRZ + FULL_NAME + MINI_FACIAL + SIGNATURE)

#Apply initial encodements on relevant sections of the barcode...
print ("applying first Encodements...")

#ISSUING COUNTRY c40 encode.
print("Encoding Country code", ISSUING_COUNTRY,"...")
C40_ISSUING_COUNTRY = c40_encode(ISSUING_COUNTRY)
print("Encoded Bytes of country code:", C40_ISSUING_COUNTRY)
print("Encoded Country code in hex format:", C40_ISSUING_COUNTRY.hex())

#MRZ,  replace spacebar and then C40 encode.
print("Replacing < in MRZ:", MRZ, "...")
EncodedMRZ = ReplaceLessThanSymbol(MRZ)
print("< Replaced with <Spacebar> in MRZ:")
print(EncodedMRZ)
print("Encoding MRZ...")
C40_MRZ = c40_encode(EncodedMRZ)
print("C40 MRZ:")
print(C40_MRZ)
hex_representation_C40 = ''.join([f'{byte:02x}' for byte in C40_MRZ])
print("Hexadecimal of C40 MRZ:", hex_representation_C40)

#Print out total result of initial encodements.
print("")
print("certificate in bytes", CERTIFICATE_REFERENCE)
print("CERTIFICATE REFERENCE IN HEX", CERTIFICATE_REFERENCE.hex())
print("FULL NAME:", FULL_NAME)
print("FULL NAME IN HEX:", FULL_NAME.hex())
print("SIGNATURE IN HEX:", SIGNATURE.hex())
print("ALGORITHM IN HEX:", SIGNATURE.hex())
print("RAW PAYLOAD:")
RAW_PAYLOAD = C40_ISSUING_COUNTRY + SIGNATURE_ALGORITHM + CERTIFICATE_REFERENCE + SIGNATURE_DATE + C40_MRZ + FULL_NAME + MINI_FACIAL + SIGNATURE
#RAW_PAYLOAD = C40_ISSUING_COUNTRY + SIGNATURE_ALGORITHM + CERTIFICATE_REFERENCE + SIGNATURE_DATE + C40_MRZ + FULL_NAME  + SIGNATURE

#CHECK TO SEE IF ALL PAYLOAD IS IN BYTES
if isinstance(RAW_PAYLOAD, bytes):
    hex_representation = ''.join([f'{byte:02x}' for byte in RAW_PAYLOAD])
    print("HEX REP of First encodement step; RAW_PAYLOAD:")
    print(RAW_PAYLOAD.hex())
else:
    print("Warning: data is not purely bytes.")

#Apply DER-TLV on relevant data...
data_items = {
    "MRZ": C40_MRZ,          # Use the encoded MRZ
    "MINI_FACIAL": MINI_FACIAL,
    "SIGNATURE": SIGNATURE,
    "FULL_NAME": FULL_NAME
}

print("Applying DER-TLV on...")
print("MRZ:", C40_MRZ)
print("MRZ hex:", C40_MRZ.hex())
print("MINI_FACIAL:", MINI_FACIAL)
print("SIGNATURE:", SIGNATURE)
print("SIGNATURE HEX:", SIGNATURE.hex())
print("FULL_NAME", FULL_NAME)
print("FULL_NAME HEX", FULL_NAME.hex())

encoded_results = {key: TLV_encode_data(key, value) for key, value in data_items.items()}
print("Encoded results of DER-TLV:")
print("MRZ")
print(encoded_results["MRZ"])
print("hex")
print(encoded_results["MRZ"].hex())
print("MINI FACIAL")
print(encoded_results["MINI_FACIAL"])
print("SIGNATURE")
print(encoded_results["SIGNATURE"])
print("hex")
print(encoded_results["SIGNATURE"].hex())
print("FULL NAME")
print(encoded_results["FULL_NAME"])
print("hex")
print(encoded_results["FULL_NAME"].hex())

#Apply DER-TLV on content of messagezone
print("Applying DER_TLV to the contents of the message zone")
C40_TLV_MSGZONE = encoded_results["MRZ"] + encoded_results["MINI_FACIAL"] + encoded_results["FULL_NAME"]

print("C40_TLV_MSGZONE:", C40_TLV_MSGZONE)

#Apply DER-TLV on messagezone...
print("Applying DER_TLV to C40_TLV_MSGZONE (message zone itself)...")
DER_TLV_ENCODED_MSGZONE = TLV_encode_data("MSG_ZONE", C40_TLV_MSGZONE)
print("DER_TLV_ENCODED_MSGZONE:", DER_TLV_ENCODED_MSGZONE)
print("DER_TLV_ENCODED_MSGZONE in Hex:", DER_TLV_ENCODED_MSGZONE.hex())

#Apply DER-TLV on signature zone...
SIGNATURE = encoded_results["SIGNATURE"]
print("SIGNATURE DER-TLVd: ", SIGNATURE)

PAYLOAD = C40_ISSUING_COUNTRY + SIGNATURE_ALGORITHM + CERTIFICATE_REFERENCE + SIGNATURE_DATE + DER_TLV_ENCODED_MSGZONE + SIGNATURE
print("PAYLOAD in hex: ", PAYLOAD.hex())

#Main pipeline
print("Encoding PAYLOAD with main pipeline...")
final_encodement = main_pipeline(PAYLOAD)
print("Encoding success!, removing padding...")
print("representation of final payload encodement:")
print(final_encodement)
final_encodement_nopadding = remove_base32_padding(final_encodement)
final_encodement_string = final_encodement_nopadding.decode('utf-8')
print('string...')
print(final_encodement_string)

final_barcode_string = BARCODE_FRONT + final_encodement_string
print(final_barcode_string)
print("generating QRcode...")
generate_qr_code(final_barcode_string)

#Might publicize decode section and more custom functions later.
