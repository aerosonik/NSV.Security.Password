using Microsoft.Extensions.Options;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace NSV.Security.Password
{
    /// <summary>
    /// Class based under PBKDF2 algorithm.
    /// Create hash and compare stored pass has with input pass
    /// If PasswordOptions or its property doesn't match requirements, 
    /// will be set to default values
    /// PasswordOptions requirements and default values:
    /// PasswordOptions.Iterations minimum 1000
    /// PasswordOptions.SaltLength minimum 24
    /// PasswordOptions.HashLength minimum 24
    /// PasswordOptions.MinPassLength minimum 8 maximum byte.MaxValue
    /// PasswordOptions.MaxPassLength mast > MinPassLength and = < byte.MaxValue
    /// </summary>
    internal class PasswordService: IPasswordService
    {
        private PasswordOptions _options;
        private const char _split = '|';

        //public PasswordService(IOptions<PasswordOptions> options)
        //{
        //    ValidateOptions(options.Value);
        //}

        public PasswordService(PasswordOptions options)
        {
            ValidateOptions(options);
        }

        /// <summary>
        /// Create pass hash to save it into db
        /// </summary>
        /// <param name="password">sring pass from FE</param>
        /// <returns>PasswordHashResult</returns>
        public PasswordHashResult Hash(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                return PasswordHashResult.Empty();

            if (password.Length < _options.MinPassLength)
                return PasswordHashResult.TooShort();

            if (password.Length > _options.MaxPassLength)
                return PasswordHashResult.TooLong();

            var saltBytes = new byte[_options.SaltLength];
            using var cryptoProvider = new RNGCryptoServiceProvider();
            cryptoProvider.GetBytes(saltBytes);
            using var deriveBytes = new Rfc2898DeriveBytes(
                password,
                saltBytes,
                _options.Iterations);
            var hash = deriveBytes.GetBytes(_options.HashLength);

            var passHash = $"{Convert.ToBase64String(saltBytes)}{_split}" +
                   $"{_options.Iterations}{_split}" +
                   $"{Convert.ToBase64String(hash)}";

            return PasswordHashResult.Ok(passHash);
        }

        /// <summary>
        /// Compare stored in db pass with pass from FE
        /// </summary>
        /// <param name="verifiedPassword">pass</param>
        /// <param name="originPassword">stored pass hash in db</param>
        /// <returns>PasswordValidateResult</returns>
        public PasswordValidateResult Validate(
            string verifiedPassword,
            string originPassword)
        {
            if (string.IsNullOrWhiteSpace(originPassword))
                return PasswordValidateResult.OriginEmpty();

            if (string.IsNullOrWhiteSpace(verifiedPassword))
                return PasswordValidateResult.VerifiedEmpty();

            var originHashData = HashData(originPassword);
            if (!originHashData.ok)
                return PasswordValidateResult.OriginError();

            using var deriveBytes = new Rfc2898DeriveBytes(
                verifiedPassword,
                originHashData.salt,
                originHashData.iterations);
            var verifiedPasswordHash = deriveBytes.GetBytes(originHashData.hash.Length);

            var result = Compare(originHashData.hash, verifiedPasswordHash);
            return result
                ? PasswordValidateResult.Ok()
                : PasswordValidateResult.Invalid();
        }

        private (byte[] salt, int iterations, byte[] hash, bool ok) HashData(
            string password)
        {
            var passwordItems = password.Split(_split);
            if (passwordItems.Length != 3)
                return (null, 0, null, false);

            if (passwordItems.Any(x => string.IsNullOrWhiteSpace(x)))
                return (null, 0, null, false);

            if (!int.TryParse(passwordItems[1], out var iterations))
                return (null, 0, null, false);

            byte[] salt;
            byte[] hash;
            try
            {
                salt = Convert.FromBase64String(passwordItems[0]);
                hash = Convert.FromBase64String(passwordItems[2]);
            }
            catch (FormatException)
            {
                return (null, 0, null, false);
            }

            return (salt, iterations, hash, true);
        }

        private bool Compare(ReadOnlySpan<byte> a1, ReadOnlySpan<byte> a2)
        {
            return a1.SequenceEqual(a2);
        }

        private void ValidateOptions(PasswordOptions options)
        {
            var tempOptions = new PasswordOptions();
            if (options == null)
            {
                _options = tempOptions;
                return;
            }

            _options = options;

            if (_options.HashLength < tempOptions.HashLength)
                _options.HashLength = tempOptions.HashLength;
            if (_options.Iterations < tempOptions.Iterations)
                _options.Iterations = tempOptions.Iterations;
            if (_options.SaltLength < tempOptions.SaltLength)
                _options.SaltLength = tempOptions.SaltLength;
            if (_options.MinPassLength < tempOptions.MinPassLength)
                _options.MinPassLength = tempOptions.MinPassLength;
            if (_options.MaxPassLength < _options.MinPassLength)
                _options.MaxPassLength = tempOptions.MaxPassLength;
        }
    }
}
