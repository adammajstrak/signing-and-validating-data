//# Private key PKCS8 RSA
//openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048 

//# Public key
//openssl rsa -pubout -in private.pem -out public.pem

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DataSigning;

[TestClass]
public class SignTest
{
    Crypto crypto = new Crypto();

    [TestMethod]
    public void GivenPhrase_TextTheSame_ThenGoodValidation()
    {
        var signature = crypto.SignData("Text to validate", @".\Keys\private.pem");
        var resultCheckGood = crypto.VerifyData("Text to validate", signature, @".\Keys\public.pem");

        Assert.IsTrue(resultCheckGood);
    }

    [TestMethod]
    public void GivenPhrase_TextDifferent_ThenBadValidation()
    {
        var signature = crypto.SignData("Text to validate", @".\Keys\private.pem");
        var resultCheckBad = crypto.VerifyData("Different text to validate", signature, @".\Keys\public.pem");
        Assert.IsFalse(resultCheckBad);
    }

    [TestMethod]
    public void GivenPhrase_KeyDifferent_ThenBadValidation()
    {
        var signature = crypto.SignData("Text to validate", @".\Keys\private2.pem");
        var resultCheckBad = crypto.VerifyData("Text to validate", signature, @".\Keys\public.pem");
        Assert.IsFalse(resultCheckBad);
    }
}
