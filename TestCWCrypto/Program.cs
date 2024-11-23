using System.Security.Cryptography;
using System.Text;
using TestCWCrypto;

const int BLOCK_SIZE = 32;
/*
    NOTE: when BLOCK_SIZE = n * ANOT.BLOCK_SIZE, e.g. 32, the last block could be {0}*,
          which can be solved for XORing with zero is itself.

        Diffie-Hellman Key Exchange is EAV Security.
*/

Console.WriteLine("Step 1: Key Exchange");
Console.WriteLine("Generating key...");
using var client = new ECDiffieHellmanCng()
{
    KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
    HashAlgorithm = CngAlgorithm.Sha256
};
var publicKey = client.PublicKey.ToByteArray();
Console.WriteLine($"Public Key: {Convert.ToBase64String(publicKey)}");
Console.WriteLine("Enter the public key of the other party:");
string otherKey = Console.ReadLine();
byte[] otherPublicKey = Convert.FromBase64String(otherKey);
var privateKey = client.DeriveKeyMaterial(CngKey.Import(otherPublicKey, CngKeyBlobFormat.EccPublicBlob));

Console.WriteLine("Send or Receive? (S/R)");
string action = Console.ReadLine();
if (action.ToUpper() == "R")
{
    while (true)
    {
        Console.WriteLine("Enter packages, done with empty line:");
        List<Package> received = [];
        while (true)
        {
            string line = Console.ReadLine();
            if (string.IsNullOrEmpty(line)) break;
            string[] parts = line.Split(',');
            int index = int.Parse(parts[0]);
            byte[] data = Convert.FromBase64String(parts[1]);
            byte[] signature = Convert.FromBase64String(parts[2]);
            received.Add(new Package(index, data, signature));
        }
        Console.WriteLine($"Received packages: {received.Count}");

        Console.WriteLine("Winnowing...");
        var wheat = received.Where(p => HMACHelper.Verify(privateKey, p.data, p.signature)).OrderBy(p => p.index).ToList();
        var wheatCount = wheat.Count;
        Console.WriteLine($"Wheat packages: {wheatCount}");

        Console.WriteLine("Reverse AONT...");
        byte[] assembly = new byte[wheatCount * BLOCK_SIZE];
        for (int i = 0; i < wheatCount; i++)
        {
            Array.Copy(wheat[i].data, 0, assembly, i * BLOCK_SIZE, BLOCK_SIZE);
        }
        Console.WriteLine($"Assembly: {Convert.ToBase64String(assembly)}");
        if (AONT.Reverse(assembly, out byte[] result))
        {
            Console.WriteLine($"Result: {Encoding.UTF8.GetString(result)}");
        }
        else
        {
            Console.WriteLine("Reverse failed.");
        }
        var exit = Console.ReadLine();
        if (exit.ToUpper() == "Q") break;
    }
    return;
}

Console.WriteLine("Step 2: AONT");
string content = """
    The power to authenticate is in many cases the power to control, 
    and handing all authentication power to the government is beyond all reason. 
                                                    -- Ronald L. Rivest, 1998
    """;
byte[] dataBytes = Encoding.UTF8.GetBytes(content);
byte[] transformed = AONT.Transform(dataBytes);
Console.WriteLine($"Transformed: {Convert.ToBase64String(transformed)}");

Console.WriteLine("Step 3: Packaging and Signing");
int numBlocks = (transformed.Length + BLOCK_SIZE - 1) / BLOCK_SIZE;
List<Package> packages = [];
for (int index = 0; index < numBlocks; index++)
{
    int offset = index * BLOCK_SIZE;
    int blockSize = Math.Min(BLOCK_SIZE, transformed.Length - offset);
    byte[] block = new byte[BLOCK_SIZE];
    Array.Copy(transformed, offset, block, 0, blockSize);

    byte[] signature = HMACHelper.Sign(privateKey, block);
    packages.Add(new Package(index, block, signature));
}
Console.WriteLine($"Wheat packages: {packages.Count}");

Console.WriteLine("Step 4: Adding Chaff Packages");
var rand = new Random();
int randNum = rand.Next(1, packages.Count + 1);
for (int i = 0; i < randNum; i++)
{
    var randIndex = rand.Next(0, packages.Count);
    var randData = new byte[BLOCK_SIZE];
    RandomNumberGenerator.Fill(randData);
    var randSignature = new byte[32];
    RandomNumberGenerator.Fill(randSignature);
    packages.Add(new Package(randIndex, randData, randSignature));
}
var sendPkg = packages.OrderBy(p => p.index);

Console.WriteLine("Step 5: Sending Packages");
foreach (var pkg in sendPkg)
{
    Console.WriteLine($"{pkg.index},{Convert.ToBase64String(pkg.data)},{Convert.ToBase64String(pkg.signature)}");
}
Console.ReadLine();


public record struct Package(int index, byte[] data, byte[] signature);