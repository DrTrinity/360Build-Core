namespace _360Build_Core.Interfaces;

public interface ILogger
{
    void LogSuccess(string message);
    void LogWarning(string message);
    void LogInfo(string message);
    void LogDebug(string message);
    void LogError(string message);
}