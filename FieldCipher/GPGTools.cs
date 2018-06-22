using System;
using System.IO;
using Org.BouncyCastle.Bcpg.OpenPgp;

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
    }
}
