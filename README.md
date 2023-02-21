# QOTA Unpack

A Python script for decrypting firmware encrypted using the _qotapack.exe_ utility from the QN902x SDK (previously QBlue SDK).

A QN902x chip is used, for instance, in the Viomi Smart Kettle.

## Requirements

- Python 3.6+
- `pip install -Ur requirements.txt`

## Usage example

Suppose the following command was used to encrypt the firmware:

```bash
qotapack --version=1234 --encrypt --key=11223344556677889900AABBCCDDEEFF --from=fw --to=fw.encrypted
```

To decrypt, run:

```bash
python qotaunpack.py --key=11223344556677889900AABBCCDDEEFF --from=fw.encrypted --to=fw.decrypted
```
