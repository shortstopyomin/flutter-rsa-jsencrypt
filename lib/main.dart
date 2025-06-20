import 'dart:convert';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:convert/convert.dart';
import 'package:flutter/material.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/asymmetric/rsa.dart';

void main() => runApp(const MyApp());

class MyApp extends StatelessWidget {
  const MyApp({super.key});
  @override
  Widget build(BuildContext context) {
    return const MaterialApp(home: CryptoScreen());
  }
}

class CryptoScreen extends StatefulWidget {
  const CryptoScreen({super.key});
  @override
  State<CryptoScreen> createState() => _CryptoScreenState();
}

class _CryptoScreenState extends State<CryptoScreen> {
  final String nonceHex =
      '6891702ed844695b6b90d7b212c055080bbfaf0d1e3380f6943755af4604d0dd';
  final int attempt = 4;

  // Replace with your actual PEM public key used in jsencrypt
  final String rsaPemPublicKey = '''
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvRTOQyzAL6gKmJxyK3OL
9Npm6Z+XfsKK2+G3yFMjfl7X//pweDh/5nhf0RAGUXhYOk3iK9Ha3ZgYFe3j8bNU
HkT5RkG0nZ9w65uNKZQJZKTVUn5kjG9vFE6VVWgLEacRhcqEkTHSlgZaEx3k2e+6
7H/qvOYFO2JBLKXDRumvb8k92o08CC0uJhE1TyvvP9GAb23KqT4fdNc3FXlT5Xpz
Y7jzdr0CmT2+wj1vTzY8tRGY+0zXJ9sYPmjZ19/VqJ7Iqe2KcpqGyzVoEMLFJr+1
GyI3EB0nFgy2ovqeyx5i+/l6ZTSYkYQuqQvhyMq+9FweYt9Etm0tJtOE6cgY1OJr
yQIDAQAB
-----END PUBLIC KEY-----
''';

  String _encryptedBase64 = '';
  String _error = '';

  @override
  void initState() {
    super.initState();
    _encryptData();
  }

  void _encryptData() {
    try {
      // Step 1: Combine nonce and attempt into bytes
      final Uint8List nonceBytes = Uint8List.fromList(hex.decode(nonceHex));
      final ByteData attemptByteData = ByteData(4);
      attemptByteData.setUint32(0, attempt, Endian.big);
      final Uint8List attemptBytes = attemptByteData.buffer.asUint8List();
      final Uint8List contentBytes =
      Uint8List.fromList([...nonceBytes, ...attemptBytes]);

      // Step 2: Parse public key from PEM
      final RSAPublicKey publicKey =
      CryptoUtils.rsaPublicKeyFromPem(rsaPemPublicKey);

      // Step 3: Encrypt using RSA with PKCS1 encoding
      final encryptor = RSAEngine()
        ..init(
          true,
          PublicKeyParameter<RSAPublicKey>(publicKey),
        );

      final cipherText = encryptor.process(contentBytes);

      setState(() {
        _encryptedBase64 = base64Encode(cipherText);
        _error = '';
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _encryptedBase64 = '';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    debugPrint('Encrypted Base64: $_encryptedBase64');
    return Scaffold(
      appBar: AppBar(title: const Text("RSA Encryption (jsencrypt Compatible)")),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: SingleChildScrollView(
          child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text("Encrypted (Base64, compatible with jsencrypt):",
                    style: TextStyle(fontWeight: FontWeight.bold)),
                const SizedBox(height: 8),
                SelectableText(_encryptedBase64,
                    style: const TextStyle(fontFamily: 'monospace')),
                if (_error.isNotEmpty) ...[
                  const SizedBox(height: 24),
                  Text("Error: $_error", style: const TextStyle(color: Colors.red)),
                ],
              ]),
        ),
      ),
    );
  }
}
