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


if __name__ == '__main__':
    pass
