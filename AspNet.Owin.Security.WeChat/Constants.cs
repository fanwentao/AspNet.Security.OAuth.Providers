namespace AspNet.Owin.Security.WeChat
{
    public static class Constants
    {
        public const string DefaultAuthenticationType = "WeChat";

        internal const string TokenEndpoint = "https://api.weixin.qq.com/sns/oauth2/access_token";
        internal const string AuthorizationEndpoint = "https://open.weixin.qq.com/connect/qrconnect";
        internal const string UserInformationEndpoint = "https://api.weixin.qq.com/sns/userinfo";

        internal const string CallbackPath = "/signin-wechat";

    }
}
