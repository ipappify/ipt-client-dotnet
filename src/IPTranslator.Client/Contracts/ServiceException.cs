using System;
using System.Collections.Generic;
using System.Text;

namespace IPTranslator.Contracts
{
    [Serializable]
    public class ServiceException : Exception
    {
        public virtual ResponseCode ResponseCode { get; } = ResponseCode.ServiceError;

        public ServiceException() { }
        public ServiceException(string message) : base(message) { }
        public ServiceException(string message, Exception inner) : base(message, inner) { }
        public ServiceException(ResponseCode responseCode) { ResponseCode = responseCode; }
        public ServiceException(ResponseCode responseCode, string message) : base(message) { ResponseCode = responseCode; }
        public ServiceException(ResponseCode responseCode, string message, Exception inner) : base(message, inner) { ResponseCode = responseCode; }
        protected ServiceException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}
