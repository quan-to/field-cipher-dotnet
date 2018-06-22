using System;
using System.Collections.Generic;
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
            var testKey = LoadEmbeddedResource("test-pkey.pub");
            var testKeySec = LoadEmbeddedResource("test-pkey.sec");
            Console.WriteLine($"Input: \n{jsonData}");
            Console.WriteLine("\n\n");
            var cipher = new Cipher(testKey);
            SecureRandom sr = new SecureRandom();
            byte[] key = new byte[32];
            sr.NextBytes(key);
            Console.WriteLine($"Key: {Convert.ToBase64String(key)}");
            var skipFields = new List<string> {
                Tools.CipherPathCombine("data", "User_viewer", "me", "avatar"),
            };
            Console.WriteLine(skipFields[0]);
            var encrypted = cipher.EncryptJsonFields(jsonData, key, skipFields);
            Console.WriteLine(encrypted);

            var decipher = new Decipher(testKeySec);
            if (!decipher.Unlock("1234567890")) {
                Console.WriteLine("Error decrypting key");
            }
            Console.WriteLine("--------------------------------------------------------------------------");

            var decrypted = decipher.DecryptJsonFields(encrypted, key);
            Console.WriteLine(decrypted);

            encrypted["data"]["User_viewer"]["me"]["baseName"] = encrypted["data"]["User_viewer"]["me"]["id"];
            var a = encrypted["data"]["User_viewer"]["me"]["keyAliases"][0];
            var b = encrypted["data"]["User_viewer"]["me"]["keyAliases"][1];
            encrypted["data"]["User_viewer"]["me"]["keyAliases"][0] = b;
            encrypted["data"]["User_viewer"]["me"]["keyAliases"][1] = a;

            Console.WriteLine("--------------------------------------------------------------------------");
            var decrypted2 = decipher.DecryptJsonFields(encrypted, key);
            Console.WriteLine(decrypted2);
        }
    }
}
