using System;
using System.Globalization;
using System.Security.Claims;
using AspNet.Owin.Security.Core.Common;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace AspNet.Owin.Security.Tencent.Provider
{
    public class TencentAuthenticatedContext : BaseContext
    {
        public TencentAuthenticatedContext(
            IOwinContext context,
            JObject user,
            string accessToken,
            string refreshToken,
            string expires,
            string openId) : base(context)
        {
            AccessToken = accessToken;
            OpenId = openId;
            RefreshToken = refreshToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }
            NickName = user.GetValueOrDefault("nickname");
            Gender = user.GetValueOrDefault("gender");
            FigureUrl = user.GetValueOrDefault("figureurl_qq_1");
        }

        /// <summary>
        /// 用户在QQ空间的昵称。
        /// </summary>
        public string NickName { get; }
        /// <summary>
        /// 性别。 如果获取不到则默认返回"男"
        /// </summary>
        public string Gender { get; }
        /// <summary>
        /// 大小为40×40像素的QQ头像URL。
        /// </summary>
        public string FigureUrl { get; }
        public string AccessToken { get; }
        public string RefreshToken { get; }
        /// <summary>
        /// openid是此网站上唯一对应用户身份的标识
        /// </summary>
        public string OpenId { get; }
        public TimeSpan? ExpiresIn { get; }
        public ClaimsIdentity Identity { get; set; }
        public AuthenticationProperties Properties { get; set; }

    }
}
