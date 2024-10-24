using System.Collections.Generic;
using System.Diagnostics.Metrics;

namespace JustAuthenticator.Logging;

public class JustAuthenticatorMetrics
{
    private readonly Counter<int> _authenticationErrors;
    private readonly Counter<int> _authenticationSuccesses;
    
    public JustAuthenticatorMetrics(IMeterFactory meterFactory)
    {
        var meter = meterFactory.Create("JustAuthenticator");
        _authenticationErrors = meter.CreateCounter<int>("authentication.errors");
        _authenticationSuccesses = meter.CreateCounter<int>("authentication.successes");
    }

    public void RecordAuthenticationError(string type)
    {
        _authenticationErrors.Add(1, [new KeyValuePair<string, object?>("type", type)]);
    }
    
    public void RecordAuthenticationSuccess(string? role)
    {
        _authenticationSuccesses.Add(1, [new KeyValuePair<string, object?>("role", role)]);
    }
}
