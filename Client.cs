using System.Security.Cryptography;
using System.Text;
using TestCWCrypto;

byte[] TestKeyExchange()
{
    using var alice = new ECDiffieHellmanCng()
    {
        KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
        HashAlgorithm = CngAlgorithm.Sha256
    };
    var alicePublicKey = alice.PublicKey.ToByteArray();
    using var bob = new ECDiffieHellmanCng()
    {
        KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
        HashAlgorithm = CngAlgorithm.Sha256
    };
    var bobPublicKey = bob.PublicKey.ToByteArray();
    Console.WriteLine($"Alice Public Key: {string.Join(',', alicePublicKey)}");
    Console.WriteLine($"Bob Public Key: {string.Join(',', bobPublicKey)}");

    byte[] aliceKey = alice.DeriveKeyMaterial(CngKey.Import(bobPublicKey, CngKeyBlobFormat.EccPublicBlob));
    byte[] bobKey = bob.DeriveKeyMaterial(CngKey.Import(alicePublicKey, CngKeyBlobFormat.EccPublicBlob));
    Console.WriteLine($"Alice Key: {string.Join(',', aliceKey)}");
    return aliceKey;
}


byte[] TestANOT()
{
    string data = """
    The power to authenticate is in many cases the power to control, 
    and handing all authentication power to the government is beyond all reason. 
                                                    -- Ronald L. Rivest, 1998
    """;
    byte[] dataBytes = Encoding.UTF8.GetBytes(data);
    byte[] transformed = AONT.Transform(dataBytes);
    Console.WriteLine($"Transformed:{string.Join(',', transformed)}");
    Console.ReadLine();
    if (AONT.Inverse(transformed, out byte[] result))
    {
        Console.WriteLine($"Inverse:{Encoding.UTF8.GetString(result)}");
    }
    return  transformed;
}
var key=TestKeyExchange();
var content=TestANOT();
const int BLOCK_SIZE=32;
int numBlocks=(content.Length+BLOCK_SIZE-1)/BLOCK_SIZE;
List<Package> packages = new();
for(int index=0;index<numBlocks;index++){
    int offset=index*BLOCK_SIZE;
    int blockSize=Math.Min(BLOCK_SIZE,content.Length-offset);
    byte[] block = new byte[BLOCK_SIZE];
    Array.Copy(content,offset,block,0,blockSize);

    byte[] signature = HMACHelper.Sign(key,block);
    packages.Add(new Package(index,block,signature));
}
Console.WriteLine($"wheat packages: {packages.Count}");
//Add chaff
int randNum=new Random().Next(1,packages.Count+1);
for(int i=0;i<randNum;i++){
    var randIndex=new Random().Next(0,packages.Count);
    var randData=new byte[BLOCK_SIZE];
    RandomNumberGenerator.Fill(randData);
    var randSignature=new byte[32];
    RandomNumberGenerator.Fill(randSignature);
    packages.Add(new Package(randIndex,randData,randSignature));
}
var sendPkg=packages.OrderBy(p=>p.index).ToList();
Console.WriteLine($"send packages: {sendPkg.Count}");

public record struct Package(int index,byte[] data,byte[] signature);