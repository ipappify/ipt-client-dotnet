using System;
using System.Collections.Generic;
using System.Text;

namespace IPTranslator.Contracts
{
    [Serializable]
    public class QuotaExceededException : ServiceException
    {
        public virtual string UpgradeUri { get; }

        public QuotaExceededException(string message, string upgradeUri) : base(ResponseCode.QuotaExceeded, message) { UpgradeUri = upgradeUri; }
        protected QuotaExceededException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}
