using System;
using Newtonsoft.Json.Linq;

namespace FieldCipher.Models {
    public struct FieldCipherPacket {
        public string EncryptedKey { get; set; }
        public JObject EncryptedJSON { get; set; }
    }
}
