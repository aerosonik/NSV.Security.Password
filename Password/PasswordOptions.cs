using System;
using System.Collections.Generic;
using System.Text;

namespace NSV.Security.Password
{
    public class PasswordOptions
    {
        public int Iterations { get; set; } = 1000;
        public int SaltLength { get; set; } = 24;
        public int HashLength { get; set; } = 24;
        public byte MinPassLength { get; set; } = 8;
        public byte MaxPassLength { get; set; } = byte.MaxValue;

    }
}
