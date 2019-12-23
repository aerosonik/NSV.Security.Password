using System;
using System.Collections.Generic;
using System.Text;

namespace NSV.Security.Password
{
    public struct PasswordValidateResult
    {
        public ValidateResult Result { get; }

        public PasswordValidateResult(ValidateResult result)
        {
            Result = result;
        }

        public enum ValidateResult
        {
            Ok,
            Invalid,
            VerifiedPasswordEmpty,
            OriginPasswordHashError,
            OriginPasswordHashEmpty
        }

        public static PasswordValidateResult OriginEmpty()
        {
            return new PasswordValidateResult(ValidateResult.OriginPasswordHashEmpty);
        }
        public static PasswordValidateResult VerifiedEmpty()
        {
            return new PasswordValidateResult(ValidateResult.VerifiedPasswordEmpty);
        }
        public static PasswordValidateResult Ok()
        {
            return new PasswordValidateResult(ValidateResult.Ok);
        }
        public static PasswordValidateResult Invalid()
        {
            return new PasswordValidateResult(ValidateResult.Invalid);
        }
        public static PasswordValidateResult OriginError()
        {
            return new PasswordValidateResult(ValidateResult.OriginPasswordHashError);
        }
    }
}
