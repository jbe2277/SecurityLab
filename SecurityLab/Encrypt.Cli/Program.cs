using EncryptData;
using Microsoft.Extensions.Configuration;

namespace Encrypt.Cli;

internal class Program
{
    // Examples: --Mode=Encrypt --InputFile=Test.txt --OutputFile=Encrypted.dat --Password=secret
    //           --Mode=Decrypt --InputFile=Encrypted.dat --OutputFile=Test2.txt --Password=secret

    private static void Main(string[] args)
    {
        var cfgRoot = new ConfigurationBuilder().AddCommandLine(args).Build();
        AppConfig? cfg = cfgRoot.Get<AppConfig>();
        if (cfg?.InputFile is null) throw new InvalidOperationException("Parameter InputFile is missing");
        if (cfg?.OutputFile is null) throw new InvalidOperationException("Parameter OutputFile is missing");
        if (cfg?.Password is null) throw new InvalidOperationException("Parameter Password is missing");

        using var input = File.OpenRead(cfg.InputFile);
        using var output = File.OpenWrite(cfg.OutputFile);
        if (cfg.Mode == Mode.Encrypt)
        {
            Encrypt(output, input, cfg.Password);
        }
        else
        {
            Decrypt(output, input, cfg.Password);
        }
    }

    private static void Encrypt(Stream output, Stream input, string password)
    {
        Span<byte> salt = stackalloc byte[CryptoHelper.SaltSize];
        CryptoHelper.CreateRandomSalt(salt);
        CryptoHelper.WriteSalt(output, salt);
        var key = CryptoHelper.KeyDerivation(password, salt);
        CryptoHelper.Encrypt(output, input, key);
    }

    private static void Decrypt(Stream output, Stream input, string password)
    {
        Span<byte> salt = stackalloc byte[CryptoHelper.SaltSize];
        CryptoHelper.ReadSalt(input, salt);
        var key = CryptoHelper.KeyDerivation(password, salt);
        CryptoHelper.Decrypt(output, input, key);
    }
}
