using System.Runtime.Serialization;

namespace _360Build_Core.Exceptions;

public class InvalidBootloaderException : Exception
{
    public InvalidBootloaderException(string message = "Invalid Bootloader") : base(message) {}
    
    protected InvalidBootloaderException(SerializationInfo info, StreamingContext context) : base(info, context) {}
}