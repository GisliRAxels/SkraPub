import base64
import zlib

def c40_decode(encoded_bytes):
    decoded_string = ""

    for i in range(0, len(encoded_bytes), 2):
        I1 = encoded_bytes[i]
        I2 = encoded_bytes[i + 1]

        if I1 == 254:  # Special case for one character padding
            decoded_string += chr(I2 - 1)
            continue

        V16 = (I1 * 256) + I2

        U1 = (V16 - 1) // 1600
        U2 = (V16 - (U1 * 1600) - 1) // 40
        U3 = V16 - (U1 * 1600) - (U2 * 40) - 1

        decoded_string += REVERSE_C40_CHART[U1] + REVERSE_C40_CHART.get(U2, "") + REVERSE_C40_CHART.get(U3, "")

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

def HeadReader(barcode_string, barcode_flag):
    if barcode_flag in ['A', 'C']:
        if len(barcode_string) < 4:
            raise ValueError("Barcode string is too short for this flag type.")
        country_identifier = barcode_string[:4]
        return {
            "Country Identifier": country_identifier
        }

    elif barcode_flag in ['B', 'D']:
        if len(barcode_string) < 22:
            raise ValueError("Barcode string is too short for this flag type.")
        country_identifier = barcode_string[:4]
        signature_algorithm = barcode_string[4:6]
        signature_creation_date = barcode_string[6:12]
        certificate_reference = barcode_string[12:22]
        return {
            "Country Identifier": country_identifier,
            "Signature Algorithm": signature_algorithm,
            "Signature Creation Date": signature_creation_date,
            "Certificate Reference": certificate_reference
        }
    else:
        raise ValueError(f"Invalid barcode flag: {barcode_flag}")
    
Input = "IDB1DPCOOXG6FHR67DSZT7SVZHRITTNMCZWLNPLWE776P4ZJ6AN36U2PCM5KIETKJOR6YYZGU74TPNC4GXOVUNDPSYYI3GB2L5OH2VDJ43GBNOKRMYDITJYO32XD7BAULVOUJ7EDAGAYDJ5LIBAQCF5LTWF4QFWJFMUSZSBKWBJAAMQZUA2K5ECOQDJGFGIZVFCUA6RYSBHWGYDEM4DSSYPAJ7HE7KPCAQZQKGIYDA5YDCUT77577D7EKACIWTMDNKAADVB6EM5SGY37UCDB4EATAGKYLBMB6H7YYAZQQOBYPR4AGJ5B7QVAZLAORXEUDLMJEGVCSDKKSYG7SANOPFPANKXNBFS22QOBTH5H4CSGPKTH6B7YEA2IB6GEYXGAOMTF657C4B3ZODO45K53GYS3STB7Z3ZSESRDOVPMMMXJJHRK3M3XHO72Q72T7KKHZ6SVKKVFX5KWB347ULFHR3V7PLJJZJF7HHOKXJMMPVPCMGW326OBA2O46HF5ORPS75Z4PUPTOMV3UEZHN5ZFYTOYTNK7BRR4AN46K5DWUO6RKHEZGJFYVDJYUZWX6XHZ7ZVBDH7TR4P5WIRVAC42ER76STYIHKFY5GRHGJSKRMPUU6TALRWHPU7G6FP7BDRDY6GNOCJ25W5ZM7TDY3WNWCL3LH6N7NS3OGYMJ433JXY2TGPS5THNNSL5464F4T3O7S33XGJP3DSJRHGLNLM2EWOHEW76Z6XXOXN6SYXJ6WZRID2PVP6NBVTVWRKC7YLZEHZ5TV2KDZ7Z6X57KP7SSP4J3DQWJZN7XXT2NLJX53HJQ4NX345U24ONOI6ISVK3IKL4LEMXVU3RSFN6B27G57X6KJH3W2YSTLZQPPIXVWXH33ZIZVGXQ232JXMGHAEI24POTYWXW33HV6HI7DHQ3WJQ3VVW5QB3TPDRG37HCYUHS64UF47JV7TX3JK7WPM7UOV46C7Z3JGF647ZXCE6WX4NLH6YEIO5V4WBGZJ7DZMNIIMS3QV5NKBV65FPNDGRDYFO7R2FZMGSFG3WNQV7TWNQKPWNRLGRFOEQ637LKS6LV5F55EH23BFBVM6IBV3MTH5V4HF26U44SY7FEHL5ZNNW5637WJY4HEZOVNLVYOWRJFWGW6IV73QKPRPB6PREWPSPKLE6LP72UJENDQ53SC2Y3JRYZPSNOJTDG6O7O7BX54YKD6LPV7EXKFZVXZRSEIZPWH2PLLE2FXHUOLF63Y4SNZJRMGHOVTKLTFVNS6PXFYYGO2T7PWVZU4GYZE52L4LZ53HH72PV6HP4SWR473D7JMHF764LY4JEY5BSURZNG77J7QOR3LSS2H2DFXSBRUK6LDTGTGS6NTFSDRF5M2NGT3X56JD64BH4CAPHKX7R3YQTW7O7W6DUL2HARYW5DOEZ3CMSI6766L7J6BP7OPUO5P6W6BETG2W7WXYLWMOQU5VWFAIZQXHXF6SEGF5D7A2T6XYKYSXOOLOK5ZQW4V5TE4WW2MH26VHO34NJGK2JG327CLPZDGOG2MLUWR3G3RPXP6IWI2HFJXRN24TY6JWW6FXM37E3GOILLZHRU643KUWH4S54FNS42XOMTMF5ERFGIZGQA73S7DWTLBK66X7NPR4OK7HC4OHS776VGUIZXNXUULMNNPP7M5SYQZNP6W6EDZPX4BF4G743VPSI6TYLRU5FY67YIJUBAQXB5HAQDCQHLPOL3AYC3WHE6DQJOEGPU2PHO7FEGDLTW572HN4P3RLPRLAI4Z3DVUD2U6UDFSRDHFNT53X33GU63KW4PNPMMHM6OP4CTV6E3GPXNB3RYZXTZ5LSIDJUENH3XI332XF2AGADZUT2U4"

identifier, flag, data = remove_prefix(Input)
print("Barcode Identifier:", identifier)
print("Barcode Flag:", flag)
print("Identifier and flag removed", data)

data = add_base32_padding(data)
print("base 32 padding added:", data)

data = base32_decode(data)
print("Base 32 decoded", data.hex())

data = decompress_data(data)
print("Decompressed:", data.hex())

Head_data = HeadReader(data)

# Access the data
country_identifier = Head_data.get("Country Identifier")
signature_algorithm = Head_data.get("Signature Algorithm")
signature_creation_date = Head_data.get("Signature Creation Date")
certificate_reference = Head_data.get("Certificate Reference")

#Header
#if issigned = A or C
# Country Identifier + 4 characters 
#if issigned = 1, (B or D)
# + Signature Algorithm + 1 characters
# + Signature Creation Date + 6 characters
# + Certificate Reference + 10 characters
#MessageZone

#SignatureZone