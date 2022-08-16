﻿using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Owin.Security.Providers.Evernote;
using Owin.Security.Providers.PayPal;
using Owin.Security.Providers.ArcGISPortal;
using Owin.Security.Providers.Typeform;
using Owin.Security.Providers.OpenID;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Host.SystemWeb;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Notifications;

namespace OwinOAuthProvidersDemo
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {

            //app.UseWelcomePage();
#if(DEBUG)
            // New code: Add the error page middleware to the pipeline. 
            app.UseErrorPage();
#endif
            // Enable the application to use a cookie to store information for the signed in user
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login")
            });
            // Use a cookie to temporarily store information about a user logging in with a third party login provider
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);


            // From using Microsoft.Owin.Security.OpenIdConnect;
            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    AuthenticationMode = Microsoft.Owin.Security.AuthenticationMode.Active
                    ,
                    AuthenticationType = "SSO Ontario Secure"
                    ,
                    Caption = "SSO Ontario Secure"
                    ,
                    ResponseType = OpenIdConnectResponseType.Code
                    ,
                    ResponseMode = OpenIdConnectResponseMode.FormPost
                    ,
                    Authority = "https://sit.login.security.gov.on.ca/rest/authorize?domain=DEVRBRDPDomain"
                    ,
                    ClientId = "BRDPCLIENT"
                    ,
                    Scope = $"{OpenIdConnectScope.OpenIdProfile} {OpenIdConnectScope.Email}"
                    ,
                    RedirectUri = "https://ontariorbrdpdev.ergobpm.com/account/logon"
                    //,
                    //ClientId = "RBRDPCLIENT"
                    ,
                    TokenValidationParameters = new TokenValidationParameters()
                    {
                        NameClaimType = "name"
                        ,
                        ValidateIssuer = false
                    }
                    ,
                    // More information on why the CookieManager needs to be set can be found here: 
                    // https://docs.microsoft.com/en-us/aspnet/samesite/owin-samesite
                    CookieManager = new SameSiteCookieManager(new SystemWebCookieManager()),
                    // OpenIdConnectAuthenticationNotifications configures OWIN to send notification of failed authentications to OnAuthenticationFailed method
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        RedirectToIdentityProvider = OnRedirectToIdentityProvider,
                        AuthenticationFailed = OnAuthenticationFailed
                    }
                }
            );

            //From using Owin.Security.Providers.OpenID;
            //app.UseOpenIDAuthentication("https://sit.login.security.gov.on.ca/oauth2/rest/authorize?response_type=code&domain=DEVRBRDPDomain&client_id=RBRDPCLIENT&scope=openid profile email&redirect_uri=https%3a%2f%2fontariorbrdpdev.ergobpm.com%2faccount%2flogon", "SSO Ontario", true);

            app.UseOpenIDAuthentication(new Owin.Security.Providers.OpenIDBase.OpenIDAuthenticationOptions
            {
                AuthenticationMode = Microsoft.Owin.Security.AuthenticationMode.Active
                ,
                Caption = "SSO Ontario"
                ,
                AuthenticationType = "SSO Ontario"
                ,
                ProviderDiscoveryUri = "https://sit.login.security.gov.on.ca/rest/authorize?response_type=code&domain=DEVRBRDPDomain&client_id=RBRDPCLIENT&scope=openid profile email"
                , 
                //"https://ontariorbrdpdev.ergobpm.com/account/logon"
                CallbackPath = new PathString("/account/logon")

            });

            #region Other Providers...
            //app.UseDeviantArtAuthentication("id", "secret");
            //app.UseUntappdAuthentication("id", "secret");
            // Uncomment the following lines to enable logging in with third party login providers
            //app.UseMicrosoftAccountAuthentication(
            //    clientId: "",
            //    clientSecret: "");

            //app.UseTwitterAuthentication(
            //   consumerKey: "",
            //   consumerSecret: "");

            //app.UseFacebookAuthentication(
            //   appId: "",
            //   appSecret: "");

            //app.UseGoogleAuthentication();

            //app.UseLinkedInAuthentication("", "");

            //app.UseYahooAuthentication("", "");

            //app.UseTripItAuthentication("", "");

            //app.UseGitHubAuthentication("", "");

            //app.UseBufferAuthentication("", "");

            //app.UseRedditAuthentication("", "");

            //app.UseStackExchangeAuthentication(
            //    clientId: "",
            //    clientSecret: "",
            //    key: "");

            //app.UseInstagramInAuthentication("", "");

            //var options = new GooglePlusAuthenticationOptions
            //{
            //    ClientId = "",
            //    ClientSecret = "",
            //    RequestOfflineAccess = true,
            //    Provider = new GooglePlusAuthenticationProvider
            //    {
            //        OnAuthenticated = async context => System.Diagnostics.Debug.WriteLine(String.Format("Refresh Token: {0}", context.RefreshToken))
            //    }
            //};
            //options.MomentTypes.Add("http://schemas.google.com/AddActivity");
            //options.MomentTypes.Add("http://schemas.google.com/CheckInActivity");
            //options.MomentTypes.Add("http://schemas.google.com/BuyActivity");
            //app.UseGooglePlusAuthentication(options);

            /*
             * Twitch sign-ins use /signin-Twitch as the URL for authentication
             *

             */

            ////Simple Twitch Sign-in
            //app.UseTwitchAuthentication("", "");

            ////More complex Twitch Sign-in
            //var opt = new TwitchAuthenticationOptions()
            //{
            //    ClientId = "",
            //    ClientSecret = "",
            //    Provider = new TwitchAuthenticationProvider()
            //    {
            //        OnAuthenticated = async z =>
            //        {
            ////            Getting the twitch users picture
            //            z.Identity.AddClaim(new Claim("Picture", z.User.GetValue("logo").ToString()));
            //        }
            ////    You should be able to access these claims with  HttpContext.GetOwinContext().Authentication.GetExternalLoginInfoAsync().Claims in your Account Controller
            //        //    Commonly used in the ExternalLoginCallback() in AccountController.cs
            //        /*

            //           if (user != null)
            //                {
            //                    var claim = (await AuthenticationManager.GetExternalLoginInfoAsync()).ExternalIdentity.Claims.First(
            //                    a => a.Type == "Picture");
            //                    user.Claims.Add(new IdentityUserClaim() { ClaimType = claim.Type, ClaimValue = claim.Value });
            //                    await SignInAsync(user, isPersistent: false);
            //                    return RedirectToLocal(returnUrl);
            //                }
            //         */
            //    }
            //};
            //app.UseTwitchAuthentication(opt);

            //app.UseOpenIDAuthentication("http://me.yahoo.com/", "Yahoo");

            //app.UseOpenIDAuthentication("https://openid.stackexchange.com/", "StackExchange");

            //app.UseOpenIDAuthentication("https://www.google.com/accounts/o8/id", "Google");

            //app.UseSteamAuthentication(applicationKey: "");

            //app.UseOpenIDAuthentication("http://orange.fr", "Orange");
            // Use OpenId provider login uri instead of discovery uri
            //app.UseOpenIDAuthentication("http://openid.orange.fr/server", "Orange", true);


            //app.UseSalesforceAuthentication(
            //    clientId: "",
            //    clientSecret: "");

            // Salesforce Option 1: don't specify explicit Endpoint config and use Production endpoint defaults
            //var salesforceOptions1 = new SalesforceAuthenticationOptions
            //{
            //    ClientId = "",
            //    ClientSecret = "",
            //    Provider = new SalesforceAuthenticationProvider()
            //    {
            //        OnAuthenticated = async context =>
            //        {
            //            System.Diagnostics.Debug.WriteLine(context.AccessToken);
            //            System.Diagnostics.Debug.WriteLine(context.RefreshToken);
            //            System.Diagnostics.Debug.WriteLine(context.OrganizationId);
            //        }
            //    }
            //};

            // Salesforce Option 2: ask for Sandbox environment; no need to know what those endpoints are
            //var salesforceOptions2 = new SalesforceAuthenticationOptions
            //{
            //    Endpoints =
            //        new SalesforceAuthenticationOptions.SalesforceAuthenticationEndpoints
            //        {
            //            Environment = Owin.Security.Providers.Salesforce.Constants.SandboxEnvironment
            //        },
            //    ClientId = "",
            //    ClientSecret = "",
            //    Provider = new SalesforceAuthenticationProvider()
            //    {
            //        OnAuthenticated = async context =>
            //        {
            //            System.Diagnostics.Debug.WriteLine(context.AccessToken);
            //            System.Diagnostics.Debug.WriteLine(context.RefreshToken);
            //            System.Diagnostics.Debug.WriteLine(context.OrganizationId);
            //        }
            //    }
            //};

            // Salesforce Option 3: explicitly specify endpoints (will take precedence over Environment choice)
            //var salesforceOptions3 = new SalesforceAuthenticationOptions
            //{
            //    Endpoints =
            //        new SalesforceAuthenticationOptions.SalesforceAuthenticationEndpoints
            //        {
            //            AuthorizationEndpoint = "https://ap1.salesforce.com/services/oauth2/authorize",
            //            TokenEndpoint = "https://ap1.salesforce.com/services/oauth2/token"
            //        },
            //    ClientId = "",
            //    ClientSecret = "",
            //    Provider = new SalesforceAuthenticationProvider()
            //    {
            //        OnAuthenticated = async context =>
            //        {
            //            System.Diagnostics.Debug.WriteLine(context.AccessToken);
            //            System.Diagnostics.Debug.WriteLine(context.RefreshToken);
            //            System.Diagnostics.Debug.WriteLine(context.OrganizationId);
            //        }
            //    }
            //};
            //app.UseSalesforceAuthentication(salesforceOptions1);

            ////app.UseShopifyAuthentication("", "");

            //app.UseArcGISOnlineAuthentication(
            //    clientId: "",
            //    clientSecret: "");

            //app.UseArcGISPortalAuthentication(new ArcGISPortalAuthenticationOptions(
            //    "My ArcGIS Portal",
            //    "https://arcgisportal.mydomain.com/",
            //    "",
            //    ""));

            //app.UseWordPressAuthentication(
            //    clientId: "",
            //    clientSecret: "");

            //app.UseDropboxAuthentication(
            //    appKey: "",
            //    appSecret: "");

            //app.UseHealthGraphAuthentication(
            //    clientId: "",
            //    clientSecret: "");

            //app.UseBoxAuthentication(
            //    appKey: "",
            //    appSecret: "");

            //app.UseBaiduAuthentication(
            //    apiKey: "",
            //    secretKey: "");

            //app.UseBattleNetAuthentication(new BattleNetAuthenticationOptions
            //{
            //	ClientId = "",
            //	ClientSecret = ""
            //});
            //app.UseBattleNetAuthentication(
            //	clientId: "",
            //	clientSecret: "");

            //app.UseAsanaAuthentication("", "");

            //app.UseEveOnlineAuthentication("", "");

            //app.UseSoundCloudAuthentication("", "");

            //app.UseFoursquareAuthentication(
            //	clientId: "",
            //	clientSecret: "");

            // PayPal no longer supports Tls 1.0 or 1.1
            // https://devblog.paypal.com/upcoming-security-changes-notice/
            // http://stackoverflow.com/questions/34939523/the-request-was-aborted-could-not-create-ssl-tls-secure-channel-sandbox-account
            // System.Net.ServicePointManager.SecurityProtocol = System.Net.ServicePointManager.SecurityProtocol | System.Net.SecurityProtocolType.Tls12;
            // The Return URL must be configured in the PayPal application to https://[hostname][:port]/signin-paypal
            // PayPalAuthenticationOptions payPalOptions = new PayPalAuthenticationOptions(true);
            // payPalOptions.ClientId = "";
            // payPalOptions.ClientSecret = "";
            // payPalOptions.Scope.Add("email");
            // payPalOptions.Scope.Add("profile");
            // payPalOptions.Scope.Add("address");
            // payPalOptions.Scope.Add("https://uri.paypal.com/services/expresscheckout");

            // app.UsePayPalAuthentication(payPalOptions);

            //app.UseWargamingAccountAuthentication("", WargamingAuthenticationOptions.Region.NorthAmerica);

            //app.UseFlickrAuthentication("", "");
            //app.UseVisualStudioAuthentication(
            //	appId: "",
            //	appSecret: "");

            //app.UseSpotifyAuthentication(
            //    clientId: "",
            //    clientSecret: "");

            //var options = new SlackAuthenticationOptions
            //{
            //    ClientId = "",
            //    ClientSecret = "",
            //    TeamId = "" // optional
            //};
            //options.Scope.Add("identify");
            //app.UseSlackAuthentication(options);

            //app.UseGitterAuthentication(
            //    clientId: "",
            //    clientSecret: ""
            //);

            //app.UseImgurAuthentication(
            //    new ImgurAuthenticationOptions
            //    {
            //        ClientId = "",
            //        ClientSecret = ""
            //    });

            //var options = new BacklogAuthenticationOptions
            //{
            //    ClientId = "",
            //    ClientSecret = "",
            //    ContractName = "",
            //    CallbackPath = new PathString(""),  // ex.new PathString("/OauthTokenRequest")
            //    Provider = new BacklogAuthenticationProvider
            //    {
            //        OnAuthenticated = async context => await System.Threading.Tasks.Task.Run(()=> { System.Diagnostics.Debug.WriteLine(String.Format("Refresh Token: {0}", context.RefreshToken)); })
            //    }
            //};

            //app.UseBacklogAuthentication(options);

            //var cosignOptions = new CosignAuthenticationOptions
            //{
            //    AuthenticationType = "Cosign",
            //    SignInAsAuthenticationType = signInAsType,
            //    CosignServer = "weblogin.umich.edu",
            //    CosignServicePort = 6663,
            //    IdentityServerHostInstance = "core1",
            //    ClientServer = "cosignservername"
            //};
            //app.UseCosignAuthentication(cosignOptions);

            //app.UseVimeoAuthentication("", "");

            //app.UseFitbitAuthentication(new FitbitAuthenticationOptions
            //{
            //    ClientId = "",
            //    ClientSecret = ""
            //});

            //app.UseOnshapeAuthentication(
            //    appKey: "",
            //    appSecret: "");
            //
            //
            //app.UseOnshapeAuthentication(new OnshapeAuthenticationOptions()
            //{
            //  AppKey = "",
            //  AppSecret = "",
            //  CallbackPath = new PathString("/oauthRedirect"),
            //  Hostname = "partner.dev.onshape.com"
            //});

            //app.UseVKontakteAuthentication("", "");

            //app.UseXingAuthentication("", "");

            //app.UseDoYouBuzzAuthentication("", "");
            //app.("", "");
            //app.UseOrcidAuthentication("","");

            //app.UseDiscordAuthentication("", "");
            //app.UseGeniAuthentication("", "");
            //app.UseMyHeritageAuthentication("", "");

            //app.UseWSO2Authentication("", "", "");

            //app.UseEvernoteAuthentication(new EvernoteAuthenticationOptions()
            //{
            //      IsSandBox = true,
            //      AppKey = "",
            //      AppSecret = ""
            //});

            //app.UsePodbeanAuthentication(new PodbeanAuthenticationOptions
            //{
            //      AppId = "",
            //      AppSecret = "",
            //      DebugUsingRequestHeadersToBuildBaseUri = true
            //});

            // WARNING:
            // Typeform doesn't supply the user's ID so use this provider for authorization only, not authentication 
            // because each time you sign in with the same Typeform account it will yield a distinct UserId.
            //var typeformOptions = new Owin.Security.Providers.Typeform.TypeformAuthenticationOptions
            //{
            //    ClientId = "",
            //    ClientSecret = "",
            //};
            //typeformOptions.Scope.Add("forms:read");
            //app.UseTypeformAuthentication(typeformOptions); 
            #endregion
        }

        private Task OnRedirectToIdentityProvider(RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            //if (!String.IsNullOrWhiteSpace(domain))
            //{
            //    context.ProtocolMessage.Parameters.Add("domain", domain);
            //    context.ProtocolMessage.DomainHint = String.IsNullOrWhiteSpace(domain) ? null : domain;
            //}
            return Task.CompletedTask;
        }

        /// <summary>
        /// Handle failed authentication requests by redirecting the user to the home page with an error in the query string
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            context.HandleResponse();
            context.Response.Redirect("/?errormessage=" + context.Exception.Message);
            return Task.CompletedTask;
        }
    }

}