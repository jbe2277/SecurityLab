using System.Security.Cryptography;

namespace EncryptData;

public record struct KeyData(byte[] Key, byte[] IV);

public static class CryptoHelper
{
    public static int SaltSize => 32;

    public static void CreateRandomSalt(Span<byte> salt)
    {
        if (salt.Length != SaltSize) throw new ArgumentException("salt must be of size SaltSize.", nameof(salt));
        RandomNumberGenerator.Fill(salt);
    }

    public static KeyData KeyDerivation(string password, ReadOnlySpan<byte> salt)
    {
        Span<byte> key = stackalloc byte[32 + 16];
        Rfc2898DeriveBytes.Pbkdf2(password, salt, key, 210_000, HashAlgorithmName.SHA512);
        return new KeyData(key[..32].ToArray(), key[32..].ToArray());
    }

    public static void WriteSalt(Stream output, ReadOnlySpan<byte> salt) => output.Write(salt);

    public static void ReadSalt(Stream input, Span<byte> salt) 
    {
        if (salt.Length != SaltSize) throw new ArgumentException("salt must be of size SaltSize.", nameof(salt));
        input.ReadExactly(salt);
    }

    public static void Encrypt(Stream output, Stream input, KeyData keyData)
    {
        using Aes aes = Aes.Create();
        aes.Key = keyData.Key;
        aes.IV = keyData.IV;
        using var cryptoStream = new CryptoStream(output, aes.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen: true);
        input.CopyTo(cryptoStream);
    }

    public static void Decrypt(Stream output, Stream input, KeyData keyData)
    {
        using Aes aes = Aes.Create();
        aes.Key = keyData.Key;
        aes.IV = keyData.IV;
        using var cryptoStream = new CryptoStream(input, aes.CreateDecryptor(), CryptoStreamMode.Read, leaveOpen: true);
        cryptoStream.CopyTo(output);
    }
}
