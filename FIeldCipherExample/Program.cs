using System;
using System.IO;
using System.Reflection;
using System.Text;
using FieldCipher;
using Org.BouncyCastle.Security;

namespace FieldCipherExample {
    class MainClass {

        public static string LoadEmbeddedResource(string name) {
            var assembly = Assembly.GetExecutingAssembly();
            var resourceName = $"FieldCipherExample.{name}";
            var resources = assembly.GetManifestResourceNames();
            using (Stream stream = assembly.GetManifestResourceStream(resourceName))
            using (StreamReader reader = new StreamReader(stream)) {
                string result = reader.ReadToEnd();
                return result;
            }
        }

        public static void Main(string[] args) {
            var jsonData = LoadEmbeddedResource("example.json");
            var testKey = LoadEmbeddedResource("testkey.gpg");
            Console.WriteLine($"Input: \n{jsonData}");
            Console.WriteLine("\n\n");
            var cipher = new Cipher(testKey);
            var test = cipher.EncryptToASCIIArmored(Encoding.UTF8.GetBytes(jsonData));
            SecureRandom sr = new SecureRandom();
            byte[] key = new byte[32];
            sr.NextBytes(key);
            Console.WriteLine($"Key: {Convert.ToBase64String(key)}");
            Console.WriteLine(cipher.EncryptJsonFields(jsonData, key));
        }
    }
}
