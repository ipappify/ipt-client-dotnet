using System;
using System.Collections.Generic;
using System.Text;

namespace IPTranslator.Contracts
{
    /// <summary>
    /// Similar to Http Status Codes
    /// </summary>
    public enum ResponseCode : int
    {
        OK = 200,

        Canceled = 300,
        NotReady = 301,

        BadRequest = 400,
        NotFound = 404,
        NoSuchModel = 405,

        QuotaExceeded = 419,

        ServiceError = 500
    }
}
