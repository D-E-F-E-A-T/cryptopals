#!/usr/bin/python
# Author:       https://github.com/mohabaks
# Description:  Cryptopals crypto challenges solutions
import binascii


def hex_to_base64(hex_string):
    """Convert hex to base64
    This function convert hex to base64

    Parameters
    ----------
    string : str
        hex string to be converted

    Returns
    -------
    base64_string
        A base64 string

    """
    unhexlify = binascii.unhexlify(hex_string)
    base64_string = binascii.b2a_base64(unhexlify)

    return base64_string


def fixed_xor(string1, string2):
    """Fixed XOR
    This function takes two equal-length buffers and produces their XOR
    combination.

    Parameters
    ----------
    string1 : str
        1st hex string buffer
    string2 : str
        2nd hex string buffer

    Returns
    -------
    xor_result
        Return XOR of two hex strings.

    """
    if len(string1) != len(string2):
        print("Two hex strings are not of equal-length")
        exit(1)
    else:
        unhexlify_string1 = binascii.unhexlify(string1)
        unhexlify_string2 = binascii.unhexlify(string2)
        xor_result = bytes(a ^ b for a, b in zip(unhexlify_string1,
                                                 unhexlify_string2))

        return binascii.hexlify(xor_result)


if __name__ == '__main__':
    pass
