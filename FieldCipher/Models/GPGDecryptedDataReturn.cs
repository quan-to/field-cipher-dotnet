using System;
namespace FieldCipher.Models {
    struct GPGDecryptedDataReturn {
        public String FingerPrint { get; set; }
        public String Base64Data { get; set; }
        public String Filename { get; set; }
        public bool IsIntegrityProtected { get; set; }
        public bool IsIntegrityOK { get; set; }
    }
}
