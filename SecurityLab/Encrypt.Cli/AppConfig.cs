namespace Encrypt.Cli;

internal enum Mode { Encrypt, Decrypt }

internal sealed class AppConfig
{
    public Mode Mode { get; init; }

    public string InputFile { get; init; }

    public string OutputFile { get; init; }

    public string Password { get; init; }
}
