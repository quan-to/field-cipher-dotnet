using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace FieldCipher {
    public class Cipher {

        static readonly Dictionary<JTokenType, string> JTokenType2String = new Dictionary<JTokenType, string> {
            {JTokenType.String, "string"},
            {JTokenType.Integer, "int"},
            {JTokenType.Float, "float"},
            {JTokenType.Boolean, "bool"},
            {JTokenType.Date, "date"}
        };

        readonly PgpPublicKey key;
        readonly SecureRandom sr;

        public Cipher(string gpgPubKey) {
            key = GPGTools.LoadPublicKeyFromString(gpgPubKey);
            if (key == null) {
                throw new InvalidKeyException("Invalid key provided");
            }
            sr = new SecureRandom();
        }

        public Cipher(PgpPublicKey key) {
            this.key = key;
        }

        public string EncryptToBase64(byte[] data, string filename = "encrypted-data.gpg") {
            return Convert.ToBase64String(Encrypt(data, filename));
        }

        public JObject EncryptJsonFields(string json, byte[] baseKey, List<string> skipFields = null) {
            skipFields = skipFields ?? new List<string>();
            var obj = JObject.Parse(json);
            return EncryptJsonFields(obj, baseKey, "/", skipFields);
        }

        byte[] GenDataPayload(string type, string data, string currentLevel) {
            return Encoding.UTF8.GetBytes($"({type})[{currentLevel}]{data}");
        }

        JToken EncryptArray(JToken obj, byte[] baseKey, string currentLevel, List<string> skipFields) {
            var arr = (JArray)obj;
            var o = new JToken[arr.Count];
            for (var i = 0; i < arr.Count; i++) {
                o[i] = EncryptNode(arr[i], baseKey, $"{currentLevel}{Tools.SimpleB64(i.ToString())}/", skipFields);
            }
            return JArray.FromObject(o);
        }

        JToken EncryptNode(JToken obj, byte[] baseKey, string currentLevel, List<string> skipFields) {
            if (obj.Type == JTokenType.Object) {
                return EncryptJsonFields((JObject)obj, baseKey, currentLevel, skipFields);
            }
            if (obj.Type == JTokenType.Array) {
                return EncryptArray(obj, baseKey, currentLevel, skipFields);
            }
            if (JTokenType2String.ContainsKey(obj.Type)) {
                return AESEncrypt(GenDataPayload(JTokenType2String[obj.Type], obj.ToString(), currentLevel), baseKey);
            }
            return AESEncrypt(GenDataPayload("string", obj.ToString(), currentLevel), baseKey);
        }

        JObject EncryptJsonFields(JObject obj, byte[] baseKey, string currentLevel = "/", List<string> skipFields = null) {
            skipFields = skipFields ?? new List<string>();
            foreach (var prop in obj.Properties()) {
                var nodePath = $"{currentLevel}{Tools.SimpleB64(prop.Name)}/";
                if (skipFields.IndexOf(nodePath) > -1) {
                    continue;
                }
                var o = obj[prop.Name];
                switch (o.Type) {
                    case JTokenType.Object:
                        obj[prop.Name] = EncryptJsonFields((JObject)o, baseKey, nodePath, skipFields);
                        break;
                    default:
                        obj[prop.Name] = EncryptNode(o, baseKey, nodePath, skipFields);
                        break;
                }
            }

            return obj;
        }

        string AESEncrypt(byte[] data, byte[] baseKey) {
            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new RijndaelEngine()), new ZeroBytePadding());
            var iv = new byte[16];
            var s = new MemoryStream();
            sr.NextBytes(iv);
            s.Write(iv, 0, 16);
            cipher.Init(true, new ParametersWithIV(new KeyParameter(baseKey), iv));
            var outSize = cipher.GetOutputSize(data.Length);
            byte[] output = new byte[outSize];

            var off = cipher.ProcessBytes(data, 0, data.Length, output, 0);
            s.Write(output, 0, off);
            off = cipher.DoFinal(output, 0);
            s.Write(output, 0, off);

            s.Seek(0, SeekOrigin.Begin);
            var o = s.ToArray();
            s.Close();

            return $"{Tools.MAGIC}{Convert.ToBase64String(o, 0, o.Length)}";
        }

        string EncryptToASCIIArmored(byte[] data, string filename = "encrypted-data.gpg") {
            using (var encOut = new MemoryStream()) {
                var byteData = Encrypt(data, filename);
                var s = new ArmoredOutputStream(encOut);
                s.Write(byteData, 0, byteData.Length);
                s.Close();
                encOut.Seek(0, SeekOrigin.Begin);
                var reader = new StreamReader(encOut);
                return reader.ReadToEnd();
            }
        }

        byte[] Encrypt(byte[] data, string filename = "encrypted-data.gpg") {
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
                cPk.AddMethod(key);
                var cOut = cPk.Open(encOut, bytes.Length);
                cOut.Write(bytes, 0, bytes.Length);  // obtain the actual bytes from the compressed stream
                cOut.Close();
                encOut.Seek(0, SeekOrigin.Begin);
                return encOut.ToArray();
                // endregion
            }
        }
    }
}
