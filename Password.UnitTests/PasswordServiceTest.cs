using Microsoft.Extensions.Options;
using System;
using Xunit;

namespace NSV.Security.Password.UnitTests
{
    public class PasswordServiceTest
    {
        private readonly IPasswordService _passwordService;

        public PasswordServiceTest()
        {
            var options = //Options.Create<PasswordOptions>(
                new PasswordOptions
                {
                    Iterations = 1000,
                    HashLength = 32,
                    SaltLength = 32,
                    MinPassLength = 9,
                    MaxPassLength = 20
                };
            _passwordService = PasswordServiceFactory.Create(options);
        }

        [Fact]
        public void CreatePass()
        {
            var pass = "MySecuredPassword";
            var hash = _passwordService.Hash(pass);
            Assert.True(hash.Result == PasswordHashResult.HashResult.Ok);
            Assert.NotNull(hash.Hash);
        }

        [Theory]
        [InlineData("@#$%YRMd;lsw;klef,c")]
        [InlineData("SupperDupperPass")]
        [InlineData("P@$$wordFish")]
        [InlineData("qwertyuiopasdf")]
        [InlineData("EmptyPassword")]
        public void CreateAndValidateMultiPass(string password)
        {
            var hashResult = _passwordService.Hash(password);
            Assert.True(hashResult.Result == PasswordHashResult.HashResult.Ok);
            Assert.NotNull(hashResult.Hash);

            var validateResult = _passwordService.Validate(password, hashResult.Hash);

            Assert.Equal(PasswordValidateResult.ValidateResult.Ok, validateResult.Result);
        }

        [Fact]
        public void CreatePassErrorPassToShort()
        {
            var pass = "xyz";
            var hash = _passwordService.Hash(pass);
            Assert.True(hash.Result == PasswordHashResult.HashResult.PasswordLengthTooShort);
            Assert.Null(hash.Hash);
        }

        [Fact]
        public void CreatePassErrorPassToLong()
        {
            var pass = "xyzwertyuiopasdfghjklzxcvbnm,.qwertyuiopasdfghjkl";
            var hash = _passwordService.Hash(pass);
            Assert.True(hash.Result == PasswordHashResult.HashResult.PasswordLengthTooLong);
            Assert.Null(hash.Hash);
        }

        [Fact]
        public void CreatePassErrorPassEmpty()
        {
            var pass = string.Empty;
            var hash = _passwordService.Hash(pass);
            Assert.True(hash.Result == PasswordHashResult.HashResult.PasswordEmpty);
            Assert.Null(hash.Hash);
        }

        [Fact]
        public void CreateAndValidatePassOriginError()
        {
            var password = "supperdupperpassword";
            var hashResult = _passwordService.Hash(password);
            Assert.True(hashResult.Result == PasswordHashResult.HashResult.Ok);
            Assert.NotNull(hashResult.Hash);

            var incorrectHash = hashResult.Hash.Replace("|", string.Empty);

            var validateResult = _passwordService.Validate(password, incorrectHash);

            Assert.Equal(
                PasswordValidateResult.ValidateResult.OriginPasswordHashError,
                validateResult.Result);
        }

        [Fact]
        public void CreateAndValidatePassOriginEmpty()
        {
            var password = "supperdupperpassword";

            var validateResult = _passwordService.Validate(password, string.Empty);

            Assert.Equal(
                PasswordValidateResult.ValidateResult.OriginPasswordHashEmpty,
                validateResult.Result);
        }

        [Fact]
        public void CreateAndValidatePass_ValidatedPassEmpty()
        {
            var password = "supperdupperpassword";
            var hashResult = _passwordService.Hash(password);
            var validateResult = _passwordService.Validate(string.Empty, hashResult.Hash);

            Assert.Equal(
                PasswordValidateResult.ValidateResult.VerifiedPasswordEmpty,
                validateResult.Result);
        }

        [Fact]
        public void CreateAndValidatePassInvalid()
        {
            var hashResult = _passwordService.Hash("supperdupperpassword");
            var validateResult = _passwordService.Validate("invalidpassword", hashResult.Hash);

            Assert.Equal(
                PasswordValidateResult.ValidateResult.Invalid,
                validateResult.Result);
        }

    }
}
