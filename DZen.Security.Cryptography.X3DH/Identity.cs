using System;
using System.Collections.Generic;
using System.Text;

namespace DZen.Security.Cryptography.X3DH
{
    public class Identity
    {
        public static Identity Create()
        {
            return new Identity(PrivateKey.Create());
        }

        public Identity(PrivateKey key)
        {

        }
    }
}
