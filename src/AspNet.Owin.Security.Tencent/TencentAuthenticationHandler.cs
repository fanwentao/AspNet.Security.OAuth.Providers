using System;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using AspNet.Owin.Security.Tencent.Provider;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;

namespace AspNet.Owin.Security.Tencent
{
    public class TencentAuthenticationHandler : AuthenticationHandler<TencentAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;
        public TencentAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;
            try
            {
                string code = null;
                string state = null;
                string msg = null;

                // 获取code,多个值的情况下取第一个,没有值的情况下返回null
                var values = Request.Query.GetValues(nameof(code));
                if (values != null && values.Count == 1)
                    code = values[0];

                values = Request.Query.GetValues("msg");
                if (values != null && values.Count == 1)
                    msg = values[0];

                values = Request.Query.GetValues(nameof(state));
                if (values != null && values.Count == 1)
                    state = values[0];

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                if (String.IsNullOrWhiteSpace(code))
                {
                    _logger.WriteWarning("Invalid return {0}", msg);
                    return new AuthenticationTicket(null, properties);
                }

                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                string tokenRequest = Options.TokenEndpoint +
                                      "?&grant_type=authorization_code" +
                                      "&client_id=" + Uri.EscapeDataString(Options.AppId) +
                                      "&client_secret=" + Uri.EscapeDataString(Options.AppKey) +
                                      "&code=" + Uri.EscapeDataString(code) +
                                      "&redirect_uri=" + Uri.EscapeDataString(redirectUri);

                var response = await _httpClient.GetAsync(tokenRequest, Request.CallCancelled);
                response.EnsureSuccessStatusCode();

                var queryString = await response.Content.ReadAsStringAsync();

                // 解析返回的查询字符串查询字符串
                // access_token=FE04************************CCE2&expires_in=7776000
                var nameValueCollection = HttpUtility.ParseQueryString("?" + queryString);

                string accessToken = nameValueCollection.Get("access_token"); // 授权令牌
                string expires = nameValueCollection.Get("expires_in"); // 过期时间
                string refreshToken = nameValueCollection.Get("refresh_token"); // 刷新令牌


                var openIdEndpoint = Options.OptionIdEndpoint + "?access_token=" +
                                              Uri.EscapeDataString(accessToken);

                var openIdresponse = await _httpClient.GetAsync(openIdEndpoint, Request.CallCancelled);
                openIdresponse.EnsureSuccessStatusCode();

                // 返回值 callback( {"client_id":"YOUR_APPID","openid":"YOUR_OPENID"} );
                var text = await openIdresponse.Content.ReadAsStringAsync();
                text = text.Substring(text.IndexOf('{'), text.LastIndexOf('}') - text.IndexOf('{') + 1);
                var jsonObject = JObject.Parse(text);
                var openId = jsonObject.Value<string>("openid");

                var userInformationEndpoint = Options.UserInformationEndpoint +
                                              "?access_token=" + Uri.EscapeDataString(accessToken) +
                                              "&oauth_consumer_key=" + Uri.EscapeDataString(Options.AppId) +
                                              "&openid=" + Uri.EscapeDataString(openId);

                // 请求用户信息
                var userInformationResponse = await _httpClient.GetAsync(userInformationEndpoint, Request.CallCancelled);
                userInformationResponse.EnsureSuccessStatusCode();

                var userJson = await userInformationResponse.Content.ReadAsStringAsync();

                jsonObject = JObject.Parse(userJson);

                var context = new TencentAuthenticatedContext(Context, jsonObject, accessToken, refreshToken, expires,
                    openId)
                {
                    Identity = new ClaimsIdentity(
                        Options.AuthenticationType,
                        ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType)
                };

                if (!String.IsNullOrEmpty(context.OpenId))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.OpenId, ClaimValueTypes.String, Options.AuthenticationType));
                }
                if (!String.IsNullOrEmpty(context.NickName))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Name, context.NickName, ClaimValueTypes.String, Options.AuthenticationType));
                }
                if (!String.IsNullOrEmpty(context.Gender))
                {
                    context.Identity.AddClaim(new Claim("gender", context.Gender, ClaimValueTypes.String, Options.AuthenticationType));
                }
                if (!String.IsNullOrEmpty(context.FigureUrl1))
                {
                    context.Identity.AddClaim(new Claim("figureurl_qq_1", context.FigureUrl1, ClaimValueTypes.String, Options.AuthenticationType));
                }

                if (!String.IsNullOrEmpty(context.FigureUrl2))
                {
                    context.Identity.AddClaim(new Claim("figureurl_qq_2", context.FigureUrl2, ClaimValueTypes.String, Options.AuthenticationType));
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

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Context.Response.StatusCode != 401)
                return Task.CompletedTask;


            // 查询响应的授权类型是否匹配的当前Options的授权类型的详细信息
            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri = Request.Scheme + Uri.SchemeDelimiter + Request.Host + Request.PathBase;
                string currentUri = baseUri + Request.Path + Request.QueryString;
                string redirectUri = baseUri + Options.CallbackPath;


                var properties = challenge.Properties;
                if (String.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                // http://wiki.open.qq.com/wiki/website/%E4%BD%BF%E7%94%A8Authorization_Code%E8%8E%B7%E5%8F%96Access_Token
                string scope = String.Join(", ", Options.Scope);

                // 用于保持请求和回调的状态，授权请求后原样带回给第三方。
                // 该参数可用于防止csrf攻击（跨站请求伪造攻击），建议第三方带上该参数，可设置为简单的随机数加session进行校验
                var state = Options.StateDataFormat.Protect(properties);

                var authorizationEndpoint = Options.AuthorizationEndpoint +
                                            "?response_type=code" +
                                            "&client_id=" + Uri.EscapeDataString(Options.AppId) +
                                            "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                                            "&state=" + Uri.EscapeDataString(state) +
                                            "&scope=" + Uri.EscapeDataString(scope);

                var context = new TencentApplyRedirectContext(Context, Options, authorizationEndpoint, properties);

                Options.Provider.ApplyRedirect(context);
            }

            return Task.CompletedTask;
        }

        public override async Task<bool> InvokeAsync()
        {
            if (Options.CallbackPath.HasValue && Request.Path == Options.CallbackPath)
            {
                return await InvokeReturnPathAsync();
            }
            return false;
        }

        public async Task<bool> InvokeReturnPathAsync()
        {
            var ticket = await AuthenticateCoreAsync();

            if (ticket == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new TencentReturnEndpointContext(Context, ticket)
            {
                SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                RedirectUri = ticket.Properties.RedirectUri
            };
            ticket.Properties.RedirectUri = null;

            await Options.Provider.ReturnEndpoint(context);

            if (context.Identity != null && context.SignInAsAuthenticationType != null)
            {
                var signInIdentity = context.Identity;
                if (!string.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, signInIdentity);
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

    }
}
