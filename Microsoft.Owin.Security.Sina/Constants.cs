namespace AspNet.Owin.Security.Weibo
{
    public static class Constants
    {
        public const string DefaultAuthenticationType = "Weibo";

        internal const string AuthorizationEndpoint = "https://api.weibo.com/oauth2/authorize";
        internal const string TokenEndpoint = "https://api.weibo.com/oauth2/access_token";
        internal const string UserInformationEndpoint = "https://api.weibo.com/2/users/show.json";

        internal const string CallbackPath = "/signin-weibo";

    }
}
