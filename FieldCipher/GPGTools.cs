using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using FieldCipher.Exceptions;
using FieldCipher.Models;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;

namespace FieldCipher {
    public static class GPGTools {
        public static PgpPublicKey LoadPublicKeyFromString(string key) {
            using (Stream s = Tools.GenerateStreamFromString(key)) {
                var pgp = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(s));
                foreach (PgpPublicKeyRing keyRing in pgp.GetKeyRings()) {
                    foreach (PgpPublicKey publicKey in keyRing.GetPublicKeys()) {
                        if (publicKey.IsEncryptionKey) {
                            return publicKey;
                        }
                    }
                }
            }
            return null;
        }

        public static PgpSecretKey LoadSecretKey(string key) {
            using (Stream s = Tools.GenerateStreamFromString(key)) {
                var pgp = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(s));
                foreach (PgpSecretKeyRing keyRing in pgp.GetKeyRings()) {
                    foreach (PgpSecretKey secretKey in keyRing.GetSecretKeys()) {
                        if (secretKey.IsSigningKey) {
                            return secretKey;
                        }
                    }
                }
            }
            return null;
        }

        public static byte[] EncryptForKeys(byte[] data, PgpPublicKey[] keys, string filename = "encrypted-data.gpg") {
            return EncryptForKeys(data, keys.ToList(), filename);
        }

        public static byte[] EncryptForKeys(byte[] data, List<PgpPublicKey> keys, string filename = "encrypted-data.gpg") {
            using (MemoryStream encOut = new MemoryStream(), bOut = new MemoryStream()) {
                // region Compression
                var comData = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                var cos = comData.Open(bOut);
                var lData = new PgpLiteralDataGenerator();
                var pOut = lData.Open(
                    cos,
                    PgpLiteralData.Binary,
                    filename,
                    data.Length,
                    DateTime.UtcNow
                );

                pOut.Write(data, 0, data.Length);
                lData.Close();
                comData.Close();
                byte[] bytes = bOut.ToArray();
                // endregion
                // region Encryption
                var cPk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, new SecureRandom());
                keys.ForEach(cPk.AddMethod);
                var cOut = cPk.Open(encOut, bytes.Length);
                cOut.Write(bytes, 0, bytes.Length);  // obtain the actual bytes from the compressed stream
                cOut.Close();
                encOut.Seek(0, SeekOrigin.Begin);
                return encOut.ToArray();
                // endregion
            }
        }

        public static GPGDecryptedDataReturn Decrypt(string data, PgpPrivateKey key) {
            using (var stream = PgpUtilities.GetDecoderStream(Tools.GenerateStreamFromString(data))) {
                return DecryptStream(stream, key);
            }
        }

        public static GPGDecryptedDataReturn Decrypt(byte[] data, PgpPrivateKey key) {
            using (var stream = PgpUtilities.GetDecoderStream(new MemoryStream(data))) {
                return DecryptStream(stream, key);
            }
        }

        public static GPGDecryptedDataReturn DecryptStream(Stream stream, PgpPrivateKey key) {
            var pgpF = new PgpObjectFactory(stream);
            var o = pgpF.NextPgpObject();
            var enc = o as PgpEncryptedDataList;
            if (enc == null) {
                enc = (PgpEncryptedDataList)pgpF.NextPgpObject();
            }

            PgpPublicKeyEncryptedData pbe = null;
            string lastFingerPrint = "None";
            foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects()) {
                if (pked.KeyId == key.KeyId) {
                    pbe = pked;
                    break;
                }
            }

            if (pbe == null) {
                throw new NoKeyAvailableException("There is no payload that matches loaded key.");
            }

            var clear = pbe.GetDataStream(key);
            var plainFact = new PgpObjectFactory(clear);
            var message = plainFact.NextPgpObject();
            var outData = new GPGDecryptedDataReturn {
                FingerPrint = lastFingerPrint,
            };
            if (message is PgpCompressedData cData) {
                var pgpFact = new PgpObjectFactory(cData.GetDataStream());
                message = pgpFact.NextPgpObject();
            }

            if (message is PgpLiteralData ld) {
                outData.Filename = ld.FileName;
                var iss = ld.GetInputStream();
                byte[] buffer = new byte[16 * 1024];
                using (var ms = new MemoryStream()) {
                    int read;
                    while ((read = iss.Read(buffer, 0, buffer.Length)) > 0) {
                        ms.Write(buffer, 0, read);
                    }
                    outData.Base64Data = Convert.ToBase64String(ms.ToArray());
                }
            } else if (message is PgpOnePassSignatureList) {
                throw new PgpException("Encrypted message contains a signed message - not literal data.");
            } else {
                throw new PgpException("Message is not a simple encrypted file - type unknown.");
            }

            outData.IsIntegrityProtected = pbe.IsIntegrityProtected();

            if (outData.IsIntegrityProtected) {
                outData.IsIntegrityOK = pbe.Verify();
            }

            return outData;
        }
    }
}
