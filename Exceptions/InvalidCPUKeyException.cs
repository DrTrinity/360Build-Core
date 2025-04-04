using System.Runtime.Serialization;

namespace _360Build_Core.Exceptions;

public class InvalidCPUKeyException : Exception
{
    public InvalidCPUKeyException(string message = "Invalid CPU Key") : base(message) {}
    
    protected InvalidCPUKeyException(SerializationInfo info, StreamingContext context) : base(info, context) {}
}