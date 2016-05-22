using System;
using System.Globalization;
using System.Security.Claims;
using AspNet.Owin.Security.Core.Common;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace AspNet.Owin.Security.WeChat.Provider
{
    public class WeChatAuthenticatedContext : BaseContext
    {
        public WeChatAuthenticatedContext(
            IOwinContext context,
            JObject user,
            string accessToken,
            string refreshToken,
            string expireIn,
            string openId
            )
            : base(context)
        {
            AccessToken = accessToken;
            RefreshToken = refreshToken;
            OpenId = openId;
            User = user;
            int expiresValue;
            if (Int32.TryParse(expireIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }
            NickName = user.GetValueOrDefault("nickname");
            Sex = user.GetValueOrDefault("sex");
            Province = user.GetValueOrDefault("province");
            Country = user.GetValueOrDefault("country");
            City = user.GetValueOrDefault("city");
            Unionid = user.GetValueOrDefault("unionid");
            HeadimgUrl = user.GetValueOrDefault("headimgurl");
        }

        public JObject User { get; }
        public string AccessToken { get; }
        public string RefreshToken { get; }
        public string OpenId { get; }
        public TimeSpan? ExpiresIn { get; }
        public string NickName { get; }
        public string Sex { get; }
        public string Province { get; }
        public string Country { get; }
        public string City { get; }
        public string Unionid { get; }
        public string HeadimgUrl { get; }

        public ClaimsIdentity Identity { get; set; }
        public AuthenticationProperties Properties { get; set; }

    }
}
