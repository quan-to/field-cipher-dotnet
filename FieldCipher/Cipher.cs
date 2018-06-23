using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using ContaQuanto.FieldCipher.Models;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace ContaQuanto.FieldCipher {
    public class Cipher {

        static readonly Dictionary<JTokenType, string> JTokenType2String = new Dictionary<JTokenType, string> {
            {JTokenType.String, "string"},
            {JTokenType.Integer, "int"},
            {JTokenType.Float, "float"},
            {JTokenType.Boolean, "bool"},
            {JTokenType.Date, "date"}
        };

        readonly List<PgpPublicKey> keys;
        readonly SecureRandom sr;

        public Cipher(List<string> gpgPubKey) {
            keys = gpgPubKey.Select((a) => GPGTools.LoadPublicKeyFromString(a)).ToList();
            sr = new SecureRandom();
        }

        public Cipher(List<PgpPublicKey> keys) {
            this.keys = new List<PgpPublicKey>();
            keys.ForEach(this.keys.Add);
        }

        public FieldCipherPacket GenerateEncryptedPacket(JObject json, List<string> skipFields) {
            // region Generate Random Key
            byte[] key = new byte[32];
            sr.NextBytes(key);
            // endregion
            // region Encrypt Everything
            var encJson = EncryptJsonFields(json.ToString(), key, skipFields);
            var encKey = PGPEncryptToBase64(key, "field-cipher-key.gpg");
            // endregion
            // region Do the best to clear the memory
            for (int i = 0; i < 32; i ++) {
                key[i] = 0;
            }
            key = null;
            // endregion
            return new FieldCipherPacket {
                EncryptedKey = encKey,
                EncryptedJSON = encJson,
            };
        }

        public string PGPEncryptToBase64(byte[] data, string filename = "encrypted-data.gpg") {
            return Convert.ToBase64String(GPGTools.EncryptForKeys(data, keys, filename));
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
            var ob = new JObject();
            foreach (var prop in obj.Properties()) {
                var nodePath = $"{currentLevel}{Tools.SimpleB64(prop.Name)}/";
                if (skipFields.IndexOf(nodePath) > -1) {
                    continue;
                }
                var o = obj[prop.Name];
                switch (o.Type) {
                    case JTokenType.Object:
                        ob[prop.Name] = EncryptJsonFields((JObject)o, baseKey, nodePath, skipFields);
                        break;
                    default:
                        ob[prop.Name] = EncryptNode(o, baseKey, nodePath, skipFields);
                        break;
                }
            }

            return ob;
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

        string PGPEncryptToASCIIArmored(byte[] data, string filename = "encrypted-data.gpg") {
            using (var encOut = new MemoryStream()) {
                var byteData = GPGTools.EncryptForKeys(data, keys, filename);
                var s = new ArmoredOutputStream(encOut);
                s.Write(byteData, 0, byteData.Length);
                s.Close();
                encOut.Seek(0, SeekOrigin.Begin);
                var reader = new StreamReader(encOut);
                return reader.ReadToEnd();
            }
        }
    }
}
