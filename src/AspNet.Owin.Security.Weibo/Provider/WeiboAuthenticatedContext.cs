using System;
using System.Globalization;
using System.Security.Claims;
using AspNet.Owin.Security.Core.Common;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace AspNet.Owin.Security.Weibo.Provider
{
    public class WeiboAuthenticatedContext : BaseContext
    {
        public WeiboAuthenticatedContext(
            IOwinContext context,
            JObject user,
            string accessToken,
            string expiresIn) : base(context)
        {
            User = user;
            AccessToken = accessToken;

            int expiresValue;
            if (Int32.TryParse(expiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            Id = User.GetValueOrDefault("id");
            NickName = User.GetValueOrDefault("screen_name");
            Name = User.GetValueOrDefault("name");
            Description = User.GetValueOrDefault("description");
            Gender = user.GetValueOrDefault("gender");
            ProfileImageUrl = user.GetValueOrDefault("profile_image_url");
        }

        public JObject User { get; }
        public string AccessToken { get; }
        public TimeSpan? ExpiresIn { get; }
        /// <summary>
        /// 获取用户标识
        /// </summary>
        public string Id { get; }
        /// <summary>
        /// 获取用户昵称
        /// </summary>
        public string NickName { get; }
        /// <summary>
        /// 获取用户友好显示名称
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// 获取用户个人描述
        /// </summary>
        public string Description { get; }
        /// <summary>
        /// 获取用户头像地址
        /// </summary>
        public string ProfileImageUrl { get; }
        /// <summary>
        /// 获取用户性别,性别，m：男、f：女、n：未知
        /// </summary>
        public string Gender { get; }

        public ClaimsIdentity Identity { get; set; }
        public AuthenticationProperties Properties { get; set; }


    }
}
