using System.Collections.Generic;
using Newtonsoft.Json.Linq;

namespace AspNet.Owin.Security.WeChat.Common
{
    public static class DictionaryExtensions
    {
        public static bool TryGetValue<TValue>(this IDictionary<string, object> dic, string key, out TValue value)
        {
            object obj;
            if (dic.TryGetValue(key, out obj))
            {
                if (obj is TValue)
                {
                    value = (TValue)obj;
                    return true;
                }
            }
            value = default(TValue);
            return false;
        }

        public static string GetValueOrDefault(this JObject dic, string propertyName)
        {
            JToken value;
            return dic.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}
