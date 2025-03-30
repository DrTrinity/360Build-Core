using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Reflection;

namespace _360Build
{
    public static class ConsoleLogger
    {
        // Nested enum LogLevel within the CommandLineOutput class
        public enum LogLevel
        {
            Debug,   // 0
            Info,    // 1
            Warning, // 2
            Error,   // 3
            Fatal,    // 4
            Success
        }

        // Set the minimum log level to control the verbosity of logs
        public static LogLevel CurrentLogLevel { get; set; } = LogLevel.Debug;

        // Method to print regular messages
        public static void PrintMessage(string message, LogLevel level = LogLevel.Info)
        {
            if (ShouldLog(level))
            {
                Console.ResetColor();
                PrintFormattedMessage(message, level);
            }
        }

        public static void PrintSplash()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(@$"
       _____ _____ ____  ____        _ __    __
      |__  // ___// __ \/ __ )__  __(_) /___/ /
       /_ </ __ \/ / / / __  / / / / / / __  / 
     ___/ / /_/ / /_/ / /_/ / /_/ / / / /_/ /  
    /____/\____/\____/_____/\__,_/_/_/\__,_/   
    Version: {Assembly.GetExecutingAssembly().GetName().Version}      Made by DrTrinity");
            Console.ResetColor();
            Console.WriteLine("");
        }

        // Method to print success messages in green
        public static void PrintSuccess(string message, LogLevel level = LogLevel.Success)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            PrintFormattedMessage(message, level);
            Console.ResetColor();
        }

        // Method to print error messages in red
        public static void PrintError(string message, LogLevel level = LogLevel.Error)
        {
            if (ShouldLog(level))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                PrintFormattedMessage(message, level);
                Console.ResetColor();
            }
        }

        // Method to print warning messages in yellow
        public static void PrintWarning(string message, LogLevel level = LogLevel.Warning)
        {
            if (ShouldLog(level))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                PrintFormattedMessage(message, level);
                Console.ResetColor();
            }
        }

        // Method to print an info message in cyan
        public static void PrintInfo(string message, LogLevel level = LogLevel.Info)
        {
            if (ShouldLog(level))
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                PrintFormattedMessage(message, level);
                Console.ResetColor();
            }
        }

        public static void PrintDebug(string message, LogLevel level = LogLevel.Debug)
        {
            if (ShouldLog(level))
            {
                Console.ForegroundColor = ConsoleColor.Magenta;
                PrintFormattedMessage(message, level);
                Console.ResetColor();
            }
        }

        // Method to print messages with custom colors
        public static void PrintCustom(string message, ConsoleColor color, LogLevel level = LogLevel.Info)
        {
            if (ShouldLog(level))
            {
                Console.ForegroundColor = color;
                PrintFormattedMessage(message, level);
                Console.ResetColor();
            }
        }

        // Method to check if the message should be logged based on the log level
        private static bool ShouldLog(LogLevel level)
        {
            // The log level of the message must be greater than or equal to the current log level
            return (int)level >= (int)CurrentLogLevel;
        }

        // Method to format the message based on its log level
        private static void PrintFormattedMessage(string message, LogLevel level)
        {
            // Add log level as a prefix for each message
            string prefix = level.ToString().ToUpper();
            Console.WriteLine($"[{prefix}] {message}");
        }
    }
}
