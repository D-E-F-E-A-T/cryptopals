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


def single_byte_xor_cipher(string, key):
    """Sigle byte XOR cipher
    This function take a string and XOR'd against a single character.

    Parameters
    ----------
    string : str
        hex string to be xor
    key : int
        key used to XOR'd

    Return
    ------
    xor_result
        Return XOR'd string

    """
    xor_result = b''
    unhexlify_string = binascii.unhexlify(string)
    for byte in unhexlify_string:
        xor_result += bytes([byte ^ key])

    return xor_result


def english_frequency_score(input_bytes):
    """Compare each input byte to a character frequency
    This function returns the score of a message based on the relative
    frequency; the characters that occurs in the English language

    Parameters
    ----------
    input_bytes : bytes
        Input bytes to be compared with character frequency

    Returns
    -------
    score
        Return score of the input bytes

    """
    char_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }

    scores = sum([char_frequencies.get(chr(byte), 0) for byte in input_bytes
                  .lower()])

    return scores


def brute_single_byte_xor_cipher(string):
    """Break single byte XOR cipher
    This function break single byte XOR cipher by brute-focing the key using
    frequency analysis.

    Parameters
    ----------
    string : str
        The cipher text

    Returns
    -------
    key
        Return the key used to create the cipher text
    message
        Return decrypted message

    """
    potential_msg = [] # list of potential messages
    for key in range(1, 256):
        msg = single_byte_xor_cipher(string, key)
        score = english_frequency_score(msg)
        xor_result = {
            'plaintext': msg,
            'score': score,
            'key': key
        }
        potential_msg.append(xor_result)

    # get best score by
    # sorting the list of potential messages
    best_score = sorted(potential_msg, key=lambda k: k['score'], reverse=True)\
        [0]
    key = chr(best_score.get('key')) # Character used for XOR'd
    message = best_score.get('plaintext').decode("ascii") # decrypted message

    return message, key


if __name__ == '__main__':
    pass
