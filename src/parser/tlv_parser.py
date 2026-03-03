# ===== User-defined tag mapping (CONFIG layer) =====
UNIVERSAL_TAGS = {
    1: "BOOLEAN",
    2: "INTEGER",
    4: "OCTET STRING",
    16: "SEQUENCE",
}

MMS_CONTEXT_TAGS = {
    0: "Confirmed-RequestPDU",
    1: "Confirmed-ResponsePDU",
    2: "Initiate-Request",
    3: "Initiate-Response",
    4: "Confirmed-ServiceRequest",
}

def get_tag_map(tag_class):
    if tag_class == 0:  # Universal
        return UNIVERSAL_TAGS
    
    if tag_class == 2:  # Context-specific
        return MMS_CONTEXT_TAGS
    
    return None

def parse_tag(data, offset):
    if offset >= len(data):
        raise ValueError("Unexpected end of data")
    
    tag_byte = data[offset]

    tag_class = (tag_byte >> 6) & 0b11   # 0=Universal, 2=Context
    #check constructed or primitive (bit 6)
    constructed = (tag_byte & 0x20) != 0
    
    #Extract tag number (lower 5 bits)
    tag_number = tag_byte & 0x1F

    if tag_number == 0x1F:
        raise NotImplementedError("High-tag-number form not supported")

    tag_map = get_tag_map(tag_class)
    if tag_map is None:
        tag_map = {}

    tag_name = tag_map.get(tag_number, f"Tag-{tag_number}")

    return tag_name, tag_number, tag_class, constructed, offset + 1

def parse_length(data, offset):
    if offset >= len(data):
        raise ValueError("Unexpected end of data")
    
    first_len_byte = data[offset]

    # Short form
    if first_len_byte < 0x80:
        length = first_len_byte
        return length, offset + 1
    
    # Indefinite form    
    elif first_len_byte == 0x80:
        raise ValueError("Indefinite length encoding not supported")
    
    # Long form
    else :
        num_len_bytes = first_len_byte & 0x7F

        if offset + 1 + num_len_bytes > len(data):
            raise ValueError("Invalid long-form length")

        length_bytes = data[offset+1 : offset+1+num_len_bytes]
        length = int.from_bytes(length_bytes, byteorder="big")
        
        return length, offset+1+num_len_bytes
    

def decode_primitive(tag_class, tag_number, value): 
    if tag_class == 0:
        if tag_number == 2 : # Integer
            return int.from_bytes(value, byteorder= "big", signed=True)
        
        elif tag_number == 1 : # Boolean
            return value != b'\x00'
        
        elif tag_number == 4 : # Octet String
            return value
        
        else :
            return value  # fallback   

    else:
        return value     

def parse_value(data, offset, length, constructed, tag_number, tag_class):
    
    value_bytes = data[offset:offset + length]
    new_offset = offset + length

    # Primitive
    if not constructed:
        return decode_primitive(tag_class, tag_number, value_bytes), new_offset
    
    # Constructed
    children = []
    inner_offset = offset
    end_offset = offset + length

    while inner_offset < end_offset:
        child, inner_offset = parse_tlv(data, inner_offset)
        children.append(child)

    if inner_offset != end_offset:
        raise ValueError("Length mismatch in constructed TLV")

    return children, new_offset


def parse_tlv(data, offset):
    try:    
        start_offset = offset
        tag_name,tag_number, tag_class, constructed, offset = parse_tag(data, offset)
        length, offset = parse_length(data, offset)
        
        if offset + length > len(data):
            raise ValueError("Invalid length field (overflow)")
        
        value_start = offset
        value, offset = parse_value(data, offset, length, constructed, tag_number, tag_class)
        end_offset = offset

        tlv = {
            "tag_number": tag_number,
            "constructed": constructed,
            "tag_class": tag_class,
            "length": length,
            "value": value,
            "tag_name": tag_name,
            "start": start_offset,
            "value_start": value_start,
            "end": end_offset
        }

        return tlv, offset
    
    except Exception as e:
        raise ValueError(f"Malformed TLV at offset {offset}: {e}")

    
def pretty_print(tlv, indent = 0) :
    
    if isinstance(tlv, list):
        for node in tlv:
            pretty_print(node, indent)
        return    


    prefix = " " * indent

    print(f"{prefix}{tlv['tag_name']} (len={tlv['length']})")

    # Primitive
    if not tlv["constructed"] :
        print(f"{prefix} Value: {tlv['value']}")
        
    # Constructed
    else :
        for child in tlv["value"]:
            pretty_print(child, indent +2)


def parse_all(data):
    offset = 0
    tlvs = []

    while offset < len(data):
        tlv, offset = parse_tlv(data, offset)
        tlvs.append(tlv)
    
    return tlvs

def find_tlv_by_tag(tlv, tag_name):
    results = []

    # If list of TLVs
    if isinstance(tlv, list):
        for node in tlv:
            results.extend(find_tlv_by_tag(node, tag_name))
        return results

    # If current node matches
    if tlv["tag_name"] == tag_name:
        results.append(tlv)

    # If constructed → search children
    if tlv["constructed"]:
        for child in tlv["value"]:
            results.extend(find_tlv_by_tag(child, tag_name))

    return results

def modify_tlv_value(tlv, new_value):
    if tlv["constructed"]:
        raise ValueError("Cannot directly modify constructed TLV")

    # Update value
    tlv["value"] = new_value

    # Update length
    if isinstance(new_value, int):
        # Re-encode integer
        new_bytes = new_value.to_bytes(
            (new_value.bit_length() + 7) // 8 or 1,
            byteorder="big",
            signed=True
        )

        # BER rule for positive numbers:
        # If MSB is 1, prepend 0x00
        if new_value >= 0 and (new_bytes[0] & 0x80):
            new_bytes = b'\x00' + new_bytes

        # Ber rule for negative numbers:
        # If MSB is 0, prepend 0xFF
        if new_value < 0 and not (new_bytes[0] & 0x80):
            new_bytes = b'xff' + new_bytes

        tlv["length"] = len(new_bytes)
        
    elif isinstance(new_value, bytes):
        tlv["length"] = len(new_value)
    else:
        raise TypeError("Unsupported value type")

    return tlv


def encode_length(length):
    if length < 128:
        return bytes([length])
    else:
        length_bytes = length.to_bytes(
            (length.bit_length() + 7) // 8,
            byteorder="big"
        )
        return bytes([0x80 | len(length_bytes)]) + length_bytes

def encode_tag(tlv):
    tag_class = tlv["tag_class"] << 6
    constructed = 0x20 if tlv["constructed"] else 0x00
    tag_number = tlv["tag_number"]

    return bytes([tag_class | constructed | tag_number])

def encode_tlv(tlv):

    # Primitive
    if not tlv["constructed"]:
        if isinstance(tlv["value"], int):
            value_bytes = tlv["value"].to_bytes(
                (tlv["value"].bit_length() + 7) // 8 or 1,
                byteorder="big",
                signed=True
            )
        else:
            value_bytes = tlv["value"]

    # Constructed
    else:
        value_bytes = b''
        for child in tlv["value"]:
            value_bytes += encode_tlv(child)

    # Update length
    tlv["length"] = len(value_bytes)

    return (
        encode_tag(tlv) +
        encode_length(tlv["length"]) +
        value_bytes
    )


def main():
    # Example ASN.1 BER encoded data
    # SEQUENCE { INTEGER 1, INTEGER 2 }

    data = bytes.fromhex(input("enter hex_data:"))

    tlvs = parse_all(data)

    print("\n===== PARSED OUTPUT =====")
    pretty_print(tlvs)

    integers = find_tlv_by_tag(tlvs, "INTEGER")

    for node in integers:
        modify_tlv_value(node, 99)

    print("\n===== AFTER MODIFICATION =====")
    pretty_print(tlvs)  

    print("\n===== RE-ENCODED BYTES =====")
    encoded_bytes = b''

    for tlv in tlvs:
        encoded_bytes += encode_tlv(tlv)  

    print(encoded_bytes)
    print("HEX:", encoded_bytes.hex())

if __name__ == "__main__":
    main()
