using System.Security.Cryptography;

namespace TestCWCrypto;
public static class AONT{
    public static readonly int BLOCK_SIZE = 16;
    public static byte[] Transform(byte[] data){
        int blocks= (data.Length+BLOCK_SIZE-1)/BLOCK_SIZE;
        byte[] result = new byte[(blocks+1)*BLOCK_SIZE];//reserve one block for the hash
        byte[] key= new byte[BLOCK_SIZE];
        RandomNumberGenerator.Fill(key);

        Console.WriteLine($"Key: {string.Join(',',key)}");

        for(int i=0;i<blocks;i++){
            int offset = i*BLOCK_SIZE;
            for(int j=0;j<BLOCK_SIZE&&offset+j<data.Length;j++){
                result[offset+j]=(byte)(data[offset+j]^key[j]);
            }
        }

        for(int i=0;i<blocks*BLOCK_SIZE;i++){
            key[i%BLOCK_SIZE]^=result[i];  //key XOR with data blocks
        }
        Array.Copy(key,0,result,blocks*BLOCK_SIZE,BLOCK_SIZE);
        
        Console.WriteLine($"Last Block: {string.Join(',',key)}");

        return result;
    }

    public static bool Reverse(byte[] data,out byte[] result){
        if(data.Length%BLOCK_SIZE!=0){
            result=null;
            return false;
        }

        int oriBlocks = data.Length/BLOCK_SIZE-1;
        result= new byte[oriBlocks*BLOCK_SIZE];

        byte[] key= new byte[BLOCK_SIZE];
        Array.Copy(data,oriBlocks*BLOCK_SIZE,key,0,BLOCK_SIZE);
        Console.WriteLine($"Last Block: {string.Join(',',key)}");
        
        for(int i=0;i<oriBlocks*BLOCK_SIZE;i++){
            key[i%BLOCK_SIZE]^=data[i];  //key XOR with data blocks
        }
        Console.WriteLine($"Key: {string.Join(',',key)}");

        for(int i=0;i<oriBlocks;i++){
            int offset = i*BLOCK_SIZE;
            for(int j=0;j<BLOCK_SIZE&&offset+j<result.Length;j++){
                result[offset+j]=(byte)(data[offset+j]^key[j]);
            }
        }

        return true;
    }
}