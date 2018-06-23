using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using ContaQuanto.FieldCipher;
using Newtonsoft.Json.Linq;

namespace Quanto.FieldCipherExample {
    class MainClass {

        public static string LoadEmbeddedResource(string name) {
            var assembly = Assembly.GetExecutingAssembly();
            var resourceName = $"ContaQuanto.FieldCipherExample.{name}";
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
            var cipher = new Cipher(new List<string> { testKey });
            var skipFields = new List<string> {
                Tools.CipherPathCombine("data", "User_viewer", "me", "avatar"),
            };
            Console.WriteLine(skipFields[0]);
            var data = cipher.GenerateEncryptedPacket(JObject.Parse(jsonData), skipFields);
            Console.WriteLine($"Key: {data.EncryptedKey}");
            Console.WriteLine(data.EncryptedJSON);
            Console.WriteLine("--------------------------------------------------------------------------");

            var decipher = new Decipher(testKeySec);
            if (!decipher.Unlock("1234567890")) {
                Console.WriteLine("Error decrypting key!");
                return;
            }

            var dec = decipher.DecipherPacket(data);
            Console.WriteLine($"JSON Changed: {dec.JSONChanged}");
            Console.WriteLine("Changes: ");
            dec.UnmatchedFields.ForEach((c) => Console.WriteLine($"\t{c.Expected} => {c.Got}"));
            Console.WriteLine(dec.DecryptedData);
            Console.WriteLine("--------------------------------------------------------------------------");


            data.EncryptedJSON["data"]["User_viewer"]["me"]["baseName"] = data.EncryptedJSON["data"]["User_viewer"]["me"]["id"];
            var a = data.EncryptedJSON["data"]["User_viewer"]["me"]["keyAliases"][0];
            var b = data.EncryptedJSON["data"]["User_viewer"]["me"]["keyAliases"][1];
            data.EncryptedJSON["data"]["User_viewer"]["me"]["keyAliases"][0] = b;
            data.EncryptedJSON["data"]["User_viewer"]["me"]["keyAliases"][1] = a;

            dec = decipher.DecipherPacket(data);
            Console.WriteLine($"JSON Changed: {dec.JSONChanged}");
            Console.WriteLine("Changes: ");
            dec.UnmatchedFields.ForEach((c) => Console.WriteLine($"\t{c.Expected} => {c.Got}"));
            Console.WriteLine(dec.DecryptedData);
        }
    }
}
