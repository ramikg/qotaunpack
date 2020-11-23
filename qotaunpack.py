import argparse
import binascii
import struct
from Crypto.Cipher import AES
from construct import Struct, Int16ul, Padding, GreedyBytes

FORMAT_VERSION_SIZE = 2
SUPPORTED_FORMAT_VERSIONS = [0x10]
CRC16_INITIAL_VALUE = 0
QOTAPACK_HEADER_SIZE_IN_BYTES = 16

DECRYPTED_FIRMWARE_STRUCT = Struct(
    'firmware_version' / Int16ul,
    'data_size' / Int16ul,
    'crc' / Int16ul,
    Padding(10),
    'data' / GreedyBytes
)


class QotaUnpackUnsupportedVersionException(Exception):
    pass


class QotaUnpackWrongChecksumException(Exception):
    pass


def _parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('-k', '--key', type=binascii.unhexlify, required=True,
                        help='AES-128 key. Hex format.')
    parser.add_argument('-f', '--from', dest='_from', type=argparse.FileType('rb'), required=True,
                        help='Encrypted firmware file.')
    parser.add_argument('-t', '--to', required=True,
                        help='Decrypted firmware file.')
    parser.add_argument('--disable-checks', action='store_true',
                        help='Disable version and checksum checks, and decrypt in any case.')
    parser.add_argument('--remove-header', action='store_true',
                        help='Remove the 16-bytes header added by qotapack.')

    return parser.parse_args()


def _decrypt(key, ciphertext):
    reversed_key = key[::-1]
    cipher = AES.new(reversed_key, AES.MODE_ECB)

    reversed_ciphertext = ciphertext[::-1]
    plaintext = cipher.encrypt(reversed_ciphertext)

    return plaintext[::-1]


def _verify_decrypted_data(decrypted_data):
    parsed_data = DECRYPTED_FIRMWARE_STRUCT.parse(decrypted_data)

    checksum = binascii.crc_hqx(parsed_data.data, CRC16_INITIAL_VALUE)

    if checksum != parsed_data.crc:
        raise QotaUnpackWrongChecksumException(
                f'Expected 0x{checksum:04X}, got 0x{parsed_data.crc:04X}')


if __name__ == '__main__':
    args = _parse_args()

    with args._from as encrypted_file:
        format_version_raw = encrypted_file.read(FORMAT_VERSION_SIZE)
        format_version = struct.unpack('<H', format_version_raw)[0]
        if not args.disable_checks and format_version not in SUPPORTED_FORMAT_VERSIONS:
            raise QotaUnpackUnsupportedVersionException(f'Version {format_version} unsupported.')

        encrypted_data = encrypted_file.read()

    decrypted_data = _decrypt(args.key, encrypted_data)
    if not args.disable_checks:
        _verify_decrypted_data(decrypted_data)

    if args.remove_header:
        decrypted_data = decrypted_data[QOTAPACK_HEADER_SIZE_IN_BYTES:]

    with open(args.to, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)
