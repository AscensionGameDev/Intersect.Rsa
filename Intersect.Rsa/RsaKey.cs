using System.Security.Cryptography;

namespace Intersect.Rsa;

public class RsaKey
{
    private RSAParameters _parameters;

    public RsaKey(RSAParameters parameters)
    {
        Parameters = parameters;
    }

    public RSAParameters Parameters
    {
        get => _parameters;
        set
        {
            _parameters = value;

            try
            {
                using var rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(Parameters);
                IsPublic = rsa.PublicOnly;
            }
            catch
            {
                IsPublic = false;
            }
        }
    }

    public bool IsPublic { get; private set; }

    public RsaKey(Stream stream, bool autoClose = false)
    {
        using var rsa = new RSACryptoServiceProvider();
        var buffer = new byte[stream.Length];
        var offset = 0;
        int read;
        while ((read = stream.Read(buffer, offset, buffer.Length - offset)) > 0)
        {
            offset += read;
        }

        if (offset != buffer.Length)
        {
            throw new InvalidOperationException();
        }

        rsa.ImportCspBlob(buffer);
        Parameters = rsa.ExportParameters(!rsa.PublicOnly);

        if (autoClose)
        {
            stream.Close();
        }
    }

    public bool TryWrite(Stream stream, bool autoClose = false)
    {
        using var rsa = new RSACryptoServiceProvider();
        rsa.ImportParameters(Parameters);
        var buffer = rsa.ExportCspBlob(!rsa.PublicOnly);
        stream.Write(buffer, 0, buffer.Length);

        if (autoClose)
        {
            stream.Close();
        }

        return true;
    }
}
