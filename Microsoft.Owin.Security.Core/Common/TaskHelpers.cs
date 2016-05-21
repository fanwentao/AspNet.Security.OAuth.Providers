using System.Threading.Tasks;

namespace AspNet.Owin.Security.Core.Common
{
    public static class TaskHelpers
    {
        private static readonly Task DefaultCompleted = Task.FromResult<object>(null);
        public static Task Completed()
        {
            return DefaultCompleted;
        }
    }
}
