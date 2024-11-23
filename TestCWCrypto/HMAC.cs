using System.Security.Cryptography;

namespace TestCWCrypto;

public static class HMACHelper{
    public static byte[] Sign(byte[] key,byte[] data){
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(data);
    }
    public static bool Verify(byte[] key,byte[] data,byte[] signature){
        using var hmac = new HMACSHA256(key);
        byte[] computed = hmac.ComputeHash(data);
        return computed.Length==signature.Length&&computed.AsSpan().SequenceEqual(signature);
    }
}