using System;

namespace DZen.Security.Cryptography.X3DH
{
    public static class Extensions
    {
        public static byte[] Concat(this byte[] data, byte[] newData)
        {
            byte[] all = new byte[data.Length + newData.Length];
            Buffer.BlockCopy(data, 0, all, 0, data.Length);
            Buffer.BlockCopy(newData, 0, all, data.Length, newData.Length);
            return all;
        }

        public static byte[] Concat(this byte[] data, byte[] newData, byte[] newData1)
        {
            byte[] all = new byte[data.Length + newData.Length + newData1.Length];
            Buffer.BlockCopy(data, 0, all, 0, data.Length);
            Buffer.BlockCopy(newData, 0, all, data.Length, newData.Length);
            Buffer.BlockCopy(newData1, 0, all, data.Length + newData.Length, newData1.Length);
            return all;
        }
    }
}
