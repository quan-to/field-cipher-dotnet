using System;
using System.Collections.Generic;
using Newtonsoft.Json.Linq;

namespace FieldCipher.Models {
    public struct FieldDecipherPacket {
        public JObject DecryptedData { get; set; }
        public List<UnmatchedFields> UnmatchedFields { get; set; }
        public bool JSONChanged { get { return UnmatchedFields.Count > 0; } }
    }
}
