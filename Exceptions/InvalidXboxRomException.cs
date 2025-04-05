using System.Runtime.Serialization;

namespace _360Build_Core.Exceptions;

public class InvalidXboxRomException(string message = "Invalid XboxROM image") : Exception(message);