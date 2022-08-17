using Microsoft.Owin;
using System;
using Owin.Security.Providers.OpenIDBase;

namespace Owin.Security.Providers.OpenID
{
    /// <summary>
    /// Extension methods for using <see cref="OpenIDAuthenticationMiddleware"/>
    /// </summary>
    public static class OpenIDAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using an OpenID provider
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseOpenIDAuthentication(this IAppBuilder app, OpenIDAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            app.Use(typeof(OpenIDAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using an OpenID provider
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="providerUri">The uri of the OpenID provider</param>
        /// <param name="providerName">Name of the OpenID provider</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseOpenIDAuthentication(this IAppBuilder app, string providerUri, string providerName)
        {
            return UseOpenIDAuthentication(app, providerUri, providerName, false);
        }

        /// <summary>
        /// Authenticate users using an OpenID provider
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder" /> passed to the configuration method</param>
        /// <param name="providerUri">The uri of the OpenID provider</param>
        /// <param name="providerName">Name of the OpenID provider</param>
        /// <param name="uriIsProviderLoginUri">True if the specified uri is the provider login uri and not the provider discovery uri</param>
        /// <returns>The updated <see cref="IAppBuilder" /></returns>
        public static IAppBuilder UseOpenIDAuthentication(this IAppBuilder app, string providerUri, string providerName, bool uriIsProviderLoginUri)
        {
            var authOptions = new OpenIDAuthenticationOptions
            {
                Caption = providerName,
                AuthenticationType = providerName,
                CallbackPath = new PathString("/signin-openid" + providerName.ToLowerInvariant())
            };
            if (uriIsProviderLoginUri)
            {
                authOptions.ProviderLoginUri = providerUri;
            }
            else
            {

                authOptions.ProviderDiscoveryUri = providerUri;
            }
            return UseOpenIDAuthentication(app, authOptions);
        }

        /// <summary>
        /// Uses the open identifier authentication domain.
        /// </summary>
        /// <param name="app">The application.</param>
        /// <param name="providerUri">The provider URI.</param>
        /// <param name="providerName">Name of the provider.</param>
        /// <param name="uriIsProviderLoginUri">if set to <c>true</c> [URI is provider login URI].</param>
        /// <param name="returnUrl">The return URL.</param>
        /// <param name="domain">The domain.</param>
        /// <returns>IAppBuilder.</returns>
        public static IAppBuilder UseOpenIDAuthenticationDomain(this IAppBuilder app, string providerUri, string providerName, bool uriIsProviderLoginUri, string returnUrl = null, string domain = null)
        {
            var authOptions = new OpenIDAuthenticationOptions
            {
                Caption = providerName,
                AuthenticationType = providerName,
                CallbackPath = new PathString("/signin-openid" + providerName.ToLowerInvariant()),
                RedirectUri = returnUrl,
                Domain = domain
            };
            if (uriIsProviderLoginUri)
            {
                authOptions.ProviderLoginUri = providerUri;
            }
            else
            {
                authOptions.ProviderDiscoveryUri = providerUri;
            }
            return UseOpenIDAuthentication(app, authOptions);
        }
    }
}
