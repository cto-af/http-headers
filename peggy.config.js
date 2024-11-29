export default {
  input: 'src/index.peggy',
  format: 'es',
  dts: true,
  allowedStartRules: [
    'Headers',
    'Headers_Loose',
    'Header',
    'Accept',
    'Accept_CH',
    'Accept_Charset',
    'Accept_Encoding',
    'Accept_Language',
    'Accept_Ranges',
    'Age',
    'Allow',
    'ALPN',
    'Alt_Svc',
    'Authentication_Info',
    'Authorization',
    'Cache_Control',
    'Connection',
    'Content_Encoding',
    'Content_Language',
    'Content_Length',
    'Content_Location',
    'Content_Range',
    'Content_Security_Policy',
    'Content_Security_Policy_Report_Only',
    'Content_Type',
    'Date',
    'ETag',
    'Expect',
    'Expires',
    'From',
    'Host',
    'If_Match',
    'If_Modified_Since',
    'If_None_Match',
    'If_Range',
    'If_Unmodified_Since',
    'Last_Modified',
    'Location',
    'Max_Forwards',
    'NEL',
    'Permissions_Policy',
    'Proxy_Authenticate',
    'Proxy_Authentication_Info',
    'Proxy_Authorization',
    'Range',
    'Referer',
    'Referrer_Policy',
    'Retry_After',
    'Server',
    'Set_Cookie',
    'Strict_Transport_Security',
    'TE',
    'Trailer',
    'Upgrade',
    'User_Agent',
    'Vary',
    'Via',
    'WWW_Authenticate',
    'Unknown_Header',
  ],
  returnTypes: {
    Headers: 'Headers',
    Headers_Loose: 'Headers',
    Header: 'AnyHeader',
    Accept: 'Accept',
    Accept_CH: 'Accept_CH',
    Accept_Charset: 'Accept_Charset',
    Accept_Encoding: 'Accept_Encoding',
    Accept_Language: 'Accept_Language',
    Accept_Ranges: 'Accept_Ranges',
    Age: 'Age',
    Allow: 'Allow',
    ALPN: 'ALPN',
    Authentication_Info: 'Authentication_Info',
    Authorization: 'Authorization',
    Cache_Control: 'Cache_Control',
    Connection: 'Connection',
    Content_Encoding: 'Content_Encoding',
    Content_Language: 'Content_Language',
    Content_Length: 'Content_Length',
    Content_Location: 'Content_Location',
    Content_Range: 'Content_Range',
    Content_Security_Policy: 'Content_Security_Policy',
    Content_Security_Policy_Report_Only: 'Content_Security_Policy_Report_Only',
    Content_Type: 'Content_Type',
    Date: 'Date',
    ETag: 'ETag',
    Expect: 'Expect',
    Expires: 'Expires',
    From: 'From',
    Host: 'Host',
    If_Match: 'If_Match',
    If_Modified_Since: 'If_Modified_Since',
    If_None_Match: 'If_None_Match',
    If_Range: 'If_Range',
    If_Unmodified_Since: 'If_Unmodified_Since',
    Last_Modified: 'Last_Modified',
    Location: 'Location',
    Max_Forwards: 'Max_Forwards',
    NEL: 'NEL',
    Permissions_Policy: 'Permissions_Policy',
    Proxy_Authenticate: 'Proxy_Authenticate',
    Proxy_Authentication_Info: 'Proxy_Authentication_Info',
    Proxy_Authorization: 'Proxy_Authorization',
    Range: 'Range',
    Referer: 'Referer',
    Referrer_Policy: 'Referrer_Policy',
    Retry_After: 'Retry_After',
    Server: 'Server',
    Set_Cookie: 'Set_Cookie',
    Strict_Transport_Security: 'Strict_Transport_Security',
    TE: 'TE',
    Trailer: 'Trailer',
    Upgrade: 'Upgrade',
    User_Agent: 'User_Agent',
    Vary: 'Vary',
    Via: 'Via',
    WWW_Authenticate: 'WWW_Authenticate',
    Unknown_Header: 'Unknown_Header',
  },
};
