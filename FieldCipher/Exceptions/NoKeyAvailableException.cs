using System;
namespace ContaQuanto.FieldCipher.Exceptions {
    public class NoKeyAvailableException : Exception {
        public NoKeyAvailableException(string message) : base(message) {}
    }
}
