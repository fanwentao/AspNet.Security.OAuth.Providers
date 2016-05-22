using System;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Owin.Security.Core.Common;
using AspNet.Owin.Security.WeChat.Provider;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;

namespace AspNet.Owin.Security.WeChat
{
    public class WeChatAuthenticationHandler : AuthenticationHandler<WeChatAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public WeChatAuthenticationHandler(
            ILogger logger,
            HttpClient httpClient)
        {
            _logger = logger;
            _httpClient = httpClient;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                var query = Request.Query;

                var values = query.GetValues(nameof(code));
                if (values != null && values.Count == 1)
                    code = values[0];

                values = query.GetValues(nameof(state));
                if (values != null && values.Count == 1)
                    state = values[0];

                properties = Options.StateDataFormat.Unprotect(state);

                if (properties == null)
                    return null;

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                    return new AuthenticationTicket(null, properties);

                if (String.IsNullOrWhiteSpace(code))
                {
                    return new AuthenticationTicket(null, properties);
                }

                // 通过code获取access_token
                var tokenEndpoint = Options.TokenEndpoint +
                                    "?appid=" + Uri.EscapeDataString(Options.AppId) +
                                    "&secret=" + Uri.EscapeDataString(Options.AppSecret) +
                                    "&code=" + Uri.EscapeDataString(code) +
                                    "&grant_type=authorization_code";

                var tokenResponse = await _httpClient.GetAsync(tokenEndpoint, Request.CallCancelled);
                tokenResponse.EnsureSuccessStatusCode();

                var token = await tokenResponse.Content.ReadAsStringAsync();
                var tokenJObject = JObject.Parse(token);

                string accessToken = tokenJObject.Value<string>("access_token");
                string refreshToken = tokenJObject.Value<string>("refresh_token");
                string expireIn = tokenJObject.Value<string>("expires_in");
                string openId = tokenJObject.Value<string>("openid");

                if (String.IsNullOrWhiteSpace(accessToken))
                {
                    _logger.WriteWarning("Access token was not found");
                    return new AuthenticationTicket(null, properties);
                }

                // 获取用户个人信息
                var userInformationEndpoint = Options.UserInformationEndpoint +
                                              "?access_token=" + Uri.EscapeDataString(accessToken) +
                                              "&openid=" + Uri.EscapeDataString(openId);

                var userResponse = await _httpClient.GetAsync(userInformationEndpoint, Request.CallCancelled);
                userResponse.EnsureSuccessStatusCode();

                var userString = await userResponse.Content.ReadAsStringAsync();

                var context = new WeChatAuthenticatedContext(Context, JObject.Parse(userString), accessToken,
                    refreshToken, expireIn, openId)
                {
                    Identity = new ClaimsIdentity(
                        Options.AuthenticationType,
                        ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType)
                };


                if (String.IsNullOrEmpty(context.Unionid))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Unionid, XmlSchemaString, Options.AuthenticationType));
                }
                if (!String.IsNullOrEmpty(context.NickName))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.NickName, XmlSchemaString, Options.AuthenticationType));
                }
                if (!String.IsNullOrEmpty(context.Country))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Country, context.Country, XmlSchemaString, Options.AuthenticationType));
                }
                if (!String.IsNullOrEmpty(context.Sex))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Gender, context.Sex, XmlSchemaString, Options.AuthenticationType));
                }
                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }

        }

        public override async Task<bool> InvokeAsync()
        {
            //  在初始化之后由公共代码调用一次。如果身份验证中间件直接响应已知的专用路径，
            //  则必须重写此虚拟路径，将请求路径与其已知路径进行比较，提供适当的响应信息，并停止进一步处理。

            return await InvokeReplyPathAsync();
        }


        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                var ticket = await AuthenticateAsync();

                if (ticket == null)
                {
                    _logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new WeChatReturnEndpointContext(Context, ticket)
                {
                    RedirectUri = ticket.Properties.RedirectUri,
                    SignInAsAuthenticationType = Options.SignInAsAuthenticationType
                };
                ticket.Properties.RedirectUri = null;

                await Options.Provider.ReturnEndpoint(context);

                if (context.Identity != null && context.SignInAsAuthenticationType != null)
                {
                    var identity = context.Identity;
                    if (!String.Equals(identity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        identity = new ClaimsIdentity(identity.Claims, context.SignInAsAuthenticationType, identity.NameClaimType, identity.RoleClaimType);
                    }

                    Context.Authentication.SignIn(context.Properties, identity);
                }
                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        context.RedirectUri = WebUtilities.AddQueryString(context.RedirectUri, "error", "access_denied");
                    }
                    Response.Redirect(context.RedirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }
            return false;
        }


        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return TaskHelpers.Completed();
            }

            // 查询响应的授权类型是否匹配的当前Options的授权类型的详细信息
            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

                string currentUri =
                    baseUri +
                    Request.Path +
                    Request.QueryString;

                string redirectUri =
                    baseUri +
                    Options.CallbackPath;

                var properties = challenge.Properties;
                if (String.IsNullOrEmpty(properties.RedirectUri))
                    properties.RedirectUri = currentUri;

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                // 应用授权作用域，拥有多个作用域用逗号（,）分隔，网页应用目前仅填写snsapi_login即可
                string scope = String.Join(", ", Options.Scope);

                // 用于保持请求和回调的状态，授权请求后原样带回给第三方。
                // 该参数可用于防止csrf攻击（跨站请求伪造攻击），建议第三方带上该参数，可设置为简单的随机数加session进行校验
                string state = Options.StateDataFormat.Protect(properties);

                var authorizationEndpoint = Options.AuthorizationEndpoint +
                                            "?appid=" + Uri.EscapeDataString(Options.AppId) +
                                            "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                                            "&response_type=code" +
                                            "&scope=" + Uri.EscapeDataString(scope) +
                                            "&state=" + Uri.EscapeDataString(state);

                var context = new WeChatApplyRedirectContext(Context, Options, authorizationEndpoint, properties);

                Options.Provider.ApplyRedirect(context);

            }
            return TaskHelpers.Completed();
        }
    }
}
