using System;
using System.Collections.Generic;
using System.Text;

namespace IPTranslator.Contracts.Messaging
{
    public interface ITranslatorRequestMessage
    {
        string GetRequestId();
    }
}
