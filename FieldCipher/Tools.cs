using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace ContaQuanto.FieldCipher {
    public static class Tools {

        public static readonly string MAGIC = "FCMN";

        public static Stream GenerateStreamFromString(string s) {
            var stream = new MemoryStream();
            var writer = new StreamWriter(stream);
            writer.Write(s);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }

        public static string SimpleB64(string s) {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(s));
        }

        public static string UncipherPath(string cipherPath) {
            return String.Join("/", cipherPath
                .Split('/')
                .Select((a) => Convert.FromBase64String(a))
                .Select((a) => Encoding.UTF8.GetString(a))
                .ToArray()
                              );
        }

        public static string CipherPathCombine(params string[] nodes) {
            var combined = "/";
            foreach(var n in nodes) {
                var s = n.Split('/');
                if (s != null && s.Length > 1) {
                    foreach(var sn in s) {
                        combined += $"{sn}/";
                    }  
                } else {
                    combined += Convert.ToBase64String(Encoding.UTF8.GetBytes(n)) + "/";
                }
            }
            return combined;
        }
    }
}
