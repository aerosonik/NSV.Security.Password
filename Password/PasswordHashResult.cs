using System;
using System.Collections.Generic;
using System.Text;

namespace NSV.Security.Password
{
    public struct PasswordHashResult
    {
        public HashResult Result { get; }
        public string Hash { get; }

        public PasswordHashResult(HashResult result, string hash)
        {
            Result = result;
            Hash = hash;
        }

        public enum HashResult
        {
            Ok,
            PasswordEmpty,
            PasswordLengthTooShort,
            PasswordLengthTooLong
        }

        public static PasswordHashResult Empty()
        {
            return new PasswordHashResult(HashResult.PasswordEmpty, null);
        }
        public static PasswordHashResult Ok(string hash)
        {
            return new PasswordHashResult(HashResult.Ok, hash);
        }
        public static PasswordHashResult TooShort()
        {
            return new PasswordHashResult(HashResult.PasswordLengthTooShort, null);
        }

        public static PasswordHashResult TooLong()
        {
            return new PasswordHashResult(HashResult.PasswordLengthTooLong, null);
        }
    }

    
}
