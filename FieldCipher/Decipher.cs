using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using ContaQuanto.FieldCipher.Models;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace ContaQuanto.FieldCipher {
    public class Decipher {
        const string FieldRegex = @"\((.*)\)\[(.*)\](.*)";

        readonly Regex matcher;
        readonly PgpSecretKey secret;

        PgpPrivateKey key;

        public Decipher(string gpgPrivateKey) {
            secret = GPGTools.LoadSecretKey(gpgPrivateKey);
            matcher = new Regex(FieldRegex, RegexOptions.IgnoreCase);
        }

        public bool Unlock(string password) {
            try {
                key = secret.ExtractPrivateKey(password.ToCharArray());
                return true;
            } catch (Exception) {
                return false;
            }
        }

        public FieldDecipherPacket DecipherPacket(FieldCipherPacket packet) {
            var encryptedKey = Convert.FromBase64String(packet.EncryptedKey);
            var keyData = GPGTools.Decrypt(encryptedKey, key);
            var baseKey = Convert.FromBase64String(keyData.Base64Data);

            var encryptedJson = packet.EncryptedJSON;
            var result = DecryptJsonFields(encryptedJson, baseKey);
            return new FieldDecipherPacket {
                UnmatchedFields = result.Item2,
                DecryptedData = result.Item1,
            };
        }

        public Tuple<JObject, List<UnmatchedFields>> DecryptJsonFields(JObject input, byte[] baseKey) {
            List<UnmatchedFields> unmatched = new List<UnmatchedFields>();
            return new Tuple<JObject, List<UnmatchedFields>>(DecryptJsonFields(input, baseKey, unmatched, "/"), unmatched);
        }

        JToken DecryptArray(JToken token, byte[] baseKey, string currentLevel, List<UnmatchedFields> unmatchedFields) {
            var arr = (JArray)token;
            var o = new JToken[arr.Count];
            for (var i = 0; i < arr.Count; i++) {
                var nodePath = $"{currentLevel}{Tools.SimpleB64(i.ToString())}/";
                if (arr[i].Type == JTokenType.Object) {
                    o[i] = DecryptJsonFields((JObject)arr[i], baseKey, unmatchedFields, nodePath);
                } else if (arr[i].Type == JTokenType.String) {
                    o[i] = DecryptNode(arr[i], baseKey, unmatchedFields, nodePath);
                } else {
                    o[i] = arr[i];
                }
            }
            return JArray.FromObject(o);
        }

        JToken DecryptNode(JToken token, byte[] baseKey, List<UnmatchedFields> unmatchedFields, string path = "/") {
            if (token.Type == JTokenType.Array) {
                return DecryptArray(token, baseKey, path, unmatchedFields);
            }
            if (token.Type != JTokenType.String) {
                return token;
            }

            var encData = token.Value<string>();

            if (!encData.StartsWith(Tools.MAGIC, StringComparison.InvariantCulture)) {
                return token;
            }

            var bData = Convert.FromBase64String(encData.Substring(Tools.MAGIC.Length));
            var decData = AESDecrypt(bData, baseKey);
            var match = matcher.Match(decData);
            if (!match.Success) {
                return null;
            }

            var groups = match.Groups;
            if (groups.Count != 4) {
                return null;
            }

            var type = groups[1].Value;
            var expectedPath = groups[2].Value;
            var data = groups[3].Value;
            if (expectedPath != path) {
                var i = Tools.UncipherPath(expectedPath);
                var o = Tools.UncipherPath(path);
                unmatchedFields.Add(new UnmatchedFields {
                    Expected = i,
                    Got = o,
                });
            }

            switch (type) {
                case "int": return long.Parse(data);
                case "float": return double.Parse(data);
                case "bool": return bool.Parse(data);
                default:
                    return data;
            }
        }

        string AESDecrypt(byte[] data, byte[] baseKey) {
            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new RijndaelEngine()), new ZeroBytePadding());
            var iv = data.Take(16).ToArray();
            var d = data.Skip(16).ToArray();
            var s = new MemoryStream();
            cipher.Init(false, new ParametersWithIV(new KeyParameter(baseKey), iv));
            var outSize = cipher.GetOutputSize(d.Length);
            byte[] output = new byte[outSize];

            var off = cipher.ProcessBytes(d, 0, d.Length, output, 0);
            s.Write(output, 0, off);
            off = cipher.DoFinal(output, 0);
            s.Write(output, 0, off);

            s.Seek(0, SeekOrigin.Begin);
            var o = s.ToArray();
            s.Close();

            return Encoding.UTF8.GetString(o);
        }

        JObject DecryptJsonFields(JObject obj, byte[] baseKey, List<UnmatchedFields> unmatchedFields, string currentLevel = "/") {
            var ob = new JObject();
            foreach (var prop in obj.Properties()) {
                var nodePath = $"{currentLevel}{Tools.SimpleB64(prop.Name)}/";
                var o = obj[prop.Name];
                switch (o.Type) {
                    case JTokenType.Object:
                        ob[prop.Name] = DecryptJsonFields((JObject)o, baseKey, unmatchedFields, nodePath);
                        break;
                    default:
                        ob[prop.Name] = DecryptNode(o, baseKey, unmatchedFields, nodePath);
                        break;
                }
            }

            return ob;
        }
    }
}
