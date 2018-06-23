using System;
using Newtonsoft.Json.Linq;

namespace ContaQuanto.FieldCipher.Models {
    public struct FieldCipherPacket {
        public string EncryptedKey { get; set; }
        public JObject EncryptedJSON { get; set; }
    }
}
