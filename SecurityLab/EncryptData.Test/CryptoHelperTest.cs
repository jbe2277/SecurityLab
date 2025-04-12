using Xunit;

namespace EncryptData.Test;

public class CryptoHelperTest
{
    [Fact]
    public void EncryptDecryptTest()
    {
        var encrypted = new MemoryStream();
        EncryptText(encrypted, "top secret", "Hello World!");

        // ---------------------------------------------------------

        encrypted.Position = 0;
        var result = DecryptText(encrypted, "top secret");
        Assert.Equal("Hello World!", result);
    }

    private void EncryptText(Stream output, string password, string text)
    {
        var data = new MemoryStream();
        using (var w = new StreamWriter(data, leaveOpen: true)) { w.Write(text); }
        data.Position = 0;

        Span<byte> salt = stackalloc byte[CryptoHelper.SaltSize];
        CryptoHelper.CreateRandomSalt(salt);
        CryptoHelper.WriteSalt(output, salt);

        var key = CryptoHelper.KeyDerivation(password, salt);
        CryptoHelper.Encrypt(output, data, key);
    }

    private string DecryptText(Stream input, string password)
    {
        Span<byte> salt = stackalloc byte[CryptoHelper.SaltSize];
        CryptoHelper.ReadSalt(input, salt);

        var data = new MemoryStream();
        var key = CryptoHelper.KeyDerivation(password, salt);
        CryptoHelper.Decrypt(data, input, key);
        
        data.Position = 0;
        var r = new StreamReader(data);
        return r.ReadToEnd();
    }
}
