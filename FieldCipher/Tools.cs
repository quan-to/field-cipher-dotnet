using System;
using System.IO;
using System.Text;

namespace FieldCipher {
    public static class Tools {
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
    }
}
