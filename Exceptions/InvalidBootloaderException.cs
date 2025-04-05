using System.Runtime.Serialization;

namespace _360Build_Core.Exceptions;

public class InvalidBootloaderException(string message = "Invalid Bootloader") : Exception(message);