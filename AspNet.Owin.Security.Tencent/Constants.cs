namespace AspNet.Owin.Security.Tencent
{
    public static class Constants
    {
        public const string DefaultAuthenticationType = "Tencent";

        internal const string UserInformationEndpoint = "https://graph.qq.com/user/get_user_info";
        internal const string AuthorizationEndpoint = "https://graph.qq.com/oauth2.0/authorize";
        internal const string TokenEndpoint = "https://graph.qq.com/oauth2.0/token";
        internal const string OptionIdEndpoint = "https://graph.qq.com/oauth2.0/me";

        internal const string CallbackPath = "/signin-tencent";
    }
}
