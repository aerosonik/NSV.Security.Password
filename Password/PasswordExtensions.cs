using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Text;

namespace NSV.Security.Password
{
    public static class PasswordExtensions
    {
        public static IServiceCollection AddPassword(
           this IServiceCollection serviceCollection)
        {
            return serviceCollection
                .AddSingleton<IPasswordService>(provider =>
                {
                    return new PasswordService(new PasswordOptions());
                });
        }

        public static IServiceCollection AddPassword(
            this IServiceCollection serviceCollection,
            IConfiguration configuration)
        {
            var options = configuration
                .GetSection(nameof(PasswordOptions))
                .Get<PasswordOptions>();

            return serviceCollection
                .AddSingleton<IPasswordService>(provider =>
                {
                    return new PasswordService(options);
                });
        }

        public static IServiceCollection AddPassword(
           this IServiceCollection serviceCollection,
           Action<PasswordOptions> configureOptions)
        {
            var options = new PasswordOptions();
            configureOptions.Invoke(options);

            return serviceCollection
                .AddSingleton<IPasswordService>(provider =>
                {
                    return new PasswordService(options);
                });
        }
    }
}
