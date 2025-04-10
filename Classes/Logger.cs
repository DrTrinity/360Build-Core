using _360Build_Core.Interfaces;

namespace _360Build_Core.Classes;

public class Logger
{
    private static ILogger _logger;

    public static void Init(ILogger logger)
    {
        _logger = logger;
    }

    public static void LogSuccess(string message)
    {
        _logger.LogSuccess(message);
    }

    public static void LogWarning(string message)
    {
        _logger.LogWarning(message);
    }

    public static void LogInfo(string message)
    {
        _logger.LogInfo(message);
    }

    public static void LogDebug(string message)
    {
        _logger.LogDebug(message);
    }

    public static void LogError(string message)
    {
        _logger.LogError(message);
    }
}