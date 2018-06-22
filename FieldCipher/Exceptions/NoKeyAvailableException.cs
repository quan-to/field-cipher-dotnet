using System;
namespace FieldCipher.Exceptions {
    public class NoKeyAvailableException : Exception {
        public NoKeyAvailableException(string message) : base(message) {}
    }
}
