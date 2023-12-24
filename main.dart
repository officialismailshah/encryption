import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/src/platform_check/platform_check.dart';
Uint8List aesCbcEncrypt(
    Uint8List key, Uint8List iv, Uint8List paddedPlaintext) {
  if (![128, 192, 256].contains(key.length * 8)) {
    throw ArgumentError.value(key, 'key', 'invalid key length for AES');
  }
  if (iv.length * 8 != 128) {
    throw ArgumentError.value(iv, 'iv', 'invalid IV length for AES');
  }
  if (paddedPlaintext.length * 8 % 128 != 0) {
    throw ArgumentError.value(
        paddedPlaintext, 'paddedPlaintext', 'invalid length for AES');
  }

  final cbc = BlockCipher('AES/CBC')
    ..init(true, ParametersWithIV(KeyParameter(key), iv));

  final cipherText = Uint8List(paddedPlaintext.length);
  print("$cipherText" " encrypted length");

  var offset = 0;
  while (offset < paddedPlaintext.length) {
    offset += cbc.processBlock(paddedPlaintext, offset, cipherText, offset);
  }
  assert(offset == paddedPlaintext.length);

  return cipherText;
}
Uint8List aesCbcDecrypt(Uint8List key, Uint8List iv, Uint8List cipherText) {
  if (![128, 192, 256].contains(key.length * 8)) {
    throw ArgumentError.value(key, 'key', 'invalid key length for AES');
  }
  if (iv.length * 8 != 128) {
    throw ArgumentError.value(iv, 'iv', 'invalid IV length for AES');
  }
  if (cipherText.length * 8 % 128 != 0) {
    throw ArgumentError.value(
        cipherText, 'cipherText', 'invalid length for AES');
  }

  final cbc = BlockCipher('AES/CBC')
    ..init(false, ParametersWithIV(KeyParameter(key), iv));

  final paddedPlainText = Uint8List(cipherText.length);
  print("$paddedPlainText" "decrypted length");

  var offset = 0;
  while (offset < cipherText.length) {
    offset += cbc.processBlock(cipherText, offset, paddedPlainText, offset);
  }

  return paddedPlainText;
}
String bin2hex(Uint8List bytes, {String? separator, int? wrap}) {
  var len = 0;
  final buf = StringBuffer();
  for (final b in bytes) {
    final s = b.toRadixString(16);
    if (buf.isNotEmpty && separator != null) {
      buf.write(separator);
      len += separator.length;
    }

    if (wrap != null && wrap < len + 2) {
      buf.write('\n');
      len = 0;
    }

    buf.write('${(s.length == 1) ? '0' : ''}$s');
    len += 2;
  }
  return buf.toString();
}
Uint8List hex2bin(String hexStr) {
  if (hexStr.length % 2 != 0) {
    throw const FormatException('not an even number of hexadecimal characters');
  }
  final result = Uint8List(hexStr.length ~/ 2);
  for (var i = 0; i < result.length; i++) {
    result[i] = int.parse(hexStr.substring(2 * i, 2 * (i + 1)), radix: 16);
  }
  return result;
}
Uint8List pad(Uint8List bytes, int blockSizeBytes) {
  final padLength = blockSizeBytes - (bytes.length % blockSizeBytes);

  final padded = Uint8List(bytes.length + padLength)..setAll(0, bytes);
  Padding('PKCS7').addPadding(padded, bytes.length);

  return padded;
}
Uint8List unpad(Uint8List padded) {
  return padded.sublist(0, padded.length - Padding('PKCS7').padCount(padded));
}
Uint8List passphraseToKey(String passPhrase,
    {String salt = '', int iterations = 30000, required int bitLength}) {
  if (![128, 192, 256].contains(bitLength)) {
    throw ArgumentError.value(bitLength, 'bitLength', 'invalid for AES');
  }
  final numBytes = bitLength ~/ 8;

  final kd = KeyDerivator('SHA-256/HMAC/PBKDF2')
    ..init(Pbkdf2Parameters(utf8.encode(salt), iterations, numBytes));

  return kd.process(utf8.encode(passPhrase));
}
Uint8List? generateRandomBytes(int numBytes) {
  if (_secureRandom == null) {
    _secureRandom = SecureRandom('Fortuna');
    _secureRandom!.seed(
        KeyParameter(Platform.instance.platformEntropySource().getBytes(32)));
  }

  final iv = _secureRandom!.nextBytes(numBytes);
  return iv;
}

SecureRandom? _secureRandom;

void katTest() {
  for (var testCase in [
    [
      'CBCGFSbox128.rsp: encrypt 0',
      '00000000000000000000000000000000',
      '00000000000000000000000000000000',
      'f34481ec3cc627bacd5dc3fb08f273e6',
      '0336763e966d92595a567cc9ce537f5e',
    ],
    [
      'CBCKeySbox128.rsp: encrypt 0',
      '10a58869d74be5a374cf867cfb473859',
      '00000000000000000000000000000000',
      '00000000000000000000000000000000',
      '6d251e6944b051e04eaa6fb4dbf78465',
    ],
    [
      'CBCVarKey128.rsp: encrypt 0',
      '80000000000000000000000000000000',
      '00000000000000000000000000000000',
      '00000000000000000000000000000000',
      '0edd33d3c621e546455bd8ba1418bec8',
    ],
    [
      'CBCVarTxt128.rsp: encrypt 0',
      '00000000000000000000000000000000',
      '00000000000000000000000000000000',
      '80000000000000000000000000000000',
      '3ad78e726c1ec02b7ebfe92b23d9ec34',
    ],
    [
      'CBCGFSbox192.rsp: encrypt 0',
      '000000000000000000000000000000000000000000000000',
      '00000000000000000000000000000000',
      '1b077a6af4b7f98229de786d7516b639',
      '275cfc0413d8ccb70513c3859b1d0f72',
    ],
    [
      'CBCGFSbox256.rsp: encrypt 0',
      '0000000000000000000000000000000000000000000000000000000000000000',
      '00000000000000000000000000000000',
      '014730f80ac625fe84f026c60bfd547d',
      '5c9d844ed46f9885085e5d6a4f94c7d7',
    ]
  ]) {
    final name = testCase[0];
    final key = testCase[1];
    final iv = testCase[2];
    final plaintext = testCase[3];
    final cipherText = testCase[4];

    final cipher = aesCbcEncrypt(hex2bin(key), hex2bin(iv), hex2bin(plaintext));
    if (bin2hex(cipher) != cipherText) {
      print('$name: failed');
      throw AssertionError('$name: failed');
    }
  }

  for (var testCase in [
    [
      'CBCGFSbox128.rsp: decrypt 0',
      '00000000000000000000000000000000',
      '00000000000000000000000000000000',
      '0336763e966d92595a567cc9ce537f5e',
      'f34481ec3cc627bacd5dc3fb08f273e6',
    ],
    [
      'CBCGFSbox192.rsp: decrypt 3',
      '000000000000000000000000000000000000000000000000',
      '00000000000000000000000000000000',
      '4f354592ff7c8847d2d0870ca9481b7c',
      '51719783d3185a535bd75adc65071ce1',
    ],
    [
      'CBCGFSbox256.rsp: decrypt 4',
      '0000000000000000000000000000000000000000000000000000000000000000',
      '00000000000000000000000000000000',
      '1bc704f1bce135ceb810341b216d7abe',
      '91fbef2d15a97816060bee1feaa49afe',
    ]
  ]) {
    final name = testCase[0];
    final key = testCase[1];
    final iv = testCase[2];
    final cipherText = testCase[3];
    final plaintext = testCase[4];

    final plain = aesCbcDecrypt(hex2bin(key), hex2bin(iv), hex2bin(cipherText));
    if (bin2hex(plain) != plaintext) {
      print('$name: failed');
      throw AssertionError('$name: failed');
    }
  }
}

void encryptAndDecryptTest(int aesSize, String text) {
  const passphrase = 'p@ssw0rd';
  final randomSalt = latin1.decode(generateRandomBytes(32)!);

  final iv = generateRandomBytes(128 ~/ 8)!;

  final cipherText = aesCbcEncrypt(
      passphraseToKey(passphrase, salt: randomSalt, bitLength: aesSize),
      iv,
      pad(utf8.encode(text), 16));

  print("$cipherText **********");

  final paddedDecryptedBytes = aesCbcDecrypt(
      passphraseToKey(passphrase, salt: randomSalt, bitLength: aesSize),
      iv,
      cipherText);
  final decryptedBytes = unpad(paddedDecryptedBytes);
  final decryptedText = utf8.decode(decryptedBytes);

  print("$decryptedText decrypted*****");

  if (decryptedText != text) {
    print('decryption did not produce the original plaintext');
    throw AssertionError('encrypt/decrypt failed');
  }
}

Uint8List encryptionOnly(int aesSize, String text) {
  const passphrase = 'p@ssw0rd';
  final randomSalt = latin1.decode(generateRandomBytes(32)!);

  final iv = generateRandomBytes(128 ~/ 8)!;

  Uint8List cipher = aesCbcEncrypt(
      passphraseToKey(passphrase, salt: randomSalt, bitLength: aesSize),
      iv,
      pad(utf8.encode(text), 16));

  print("${pad(utf8.encode(text), 16)} encrypted");

  return cipher;
}

String decryptionOnly(int aesSize, Uint8List cipherText) {
  const passphrase = 'p@ssw0rd';
  final randomSalt = latin1.decode(generateRandomBytes(32)!);

  final iv = generateRandomBytes(128 ~/ 8)!;

  final paddedDecryptedBytes = aesCbcDecrypt(
      passphraseToKey(passphrase, salt: randomSalt, bitLength: aesSize),
      iv,
      cipherText);
  final decryptedBytes = unpad(paddedDecryptedBytes);

  final decryptedText = utf8.decode(decryptedBytes);

  return decryptedText;
}

void main(List<String> args) {
  if (args.contains('-h') || args.contains('--help')) {
    print('Usage: aes-cbc-registry');
    return;
  }

  katTest();

  Uint8List cipher = encryptionOnly(192, "Ismailshah");
  print(cipher);
  String decipher = decryptionOnly(192, Uint8List(cipher.length));
  print(decipher);

  print('Ok');
}
