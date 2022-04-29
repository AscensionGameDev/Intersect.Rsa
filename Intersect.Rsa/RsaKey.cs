using System.Security.Cryptography;

namespace Intersect.Rsa;

public class RsaKey
{
    public RSAParameters Parameters { get; private set; }

    public RsaKey(RSAParameters parameters)
    {
        Parameters = parameters;
    }

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
        stream.Write(buffer);

        if (autoClose)
        {
            stream.Close();
        }

        return true;
    }
}
