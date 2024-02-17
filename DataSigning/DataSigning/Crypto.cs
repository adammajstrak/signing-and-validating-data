using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using System.Text;

namespace DataSigning;
internal class Crypto
{
    public string SignData(string message, string privateKeyPath)
    {
        var privateKey = ReadAsymmetricKeyParameter(privateKeyPath);

        //Initialization
        ISigner sig = SignerUtilities.GetSigner("SHA512withRSA");
        sig.Init(true, privateKey);

        //Get bytes from message
        var bytes = Encoding.UTF8.GetBytes(message);

        //Signing data
        sig.BlockUpdate(bytes, 0, bytes.Length);
        byte[] signature = sig.GenerateSignature();

        //Return string from bytes as Base64
        return Convert.ToBase64String(signature);
    }

    public bool VerifyData(string originalMessage, string signature, string publicKeyPath)
    {
        var rsaPublicKey = GetPublicKeyCryptoProvider(publicKeyPath);

        //Get message from Base64
        var signatureBytes = Convert.FromBase64String(signature);

        //Get bytes from original message
        var bytesToVerify = new UTF8Encoding().GetBytes(originalMessage);

        //Verify data
        return rsaPublicKey.VerifyData(bytesToVerify, CryptoConfig.MapNameToOID("SHA512")!, signatureBytes);
    }

    private RSACryptoServiceProvider GetPublicKeyCryptoProvider(string publicKeyPath)
    {
        var publicKey = File.ReadAllText(publicKeyPath);

        //Read public key params
        var pr = new PemReader(new StringReader(publicKey));
        var publicKeyParams = (AsymmetricKeyParameter)pr.ReadObject();
        var rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKeyParams);

        //Create provider
        var rsaPublicKey = new RSACryptoServiceProvider();
        rsaPublicKey.ImportParameters(rsaParams);
        return rsaPublicKey;
    }
    private AsymmetricKeyParameter ReadAsymmetricKeyParameter(string privateKeyPath)
    {
        using var fileStream = File.OpenText(privateKeyPath);
        var pemReader = new PemReader(fileStream);
        return (AsymmetricKeyParameter)pemReader.ReadObject();
    }
}
