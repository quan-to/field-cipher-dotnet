using System;
using System.IO;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace FieldCipher {
    public static class GPGTools {
        public static PgpPublicKey LoadKeyFromString(string key) {
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
    }
}
