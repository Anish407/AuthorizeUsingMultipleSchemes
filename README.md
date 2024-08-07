## Authorization using different schemes

We have 3 authorization schemes
 - JWT1
 - Jwt2
 - Cookie 

<p>There are endpoints that can only be called using either JWT1, JWT2, Cookie , using any JWT token(JWT1 or JWT2) and more</p>

```
app.MapPost("Hello", Dummy);
app.MapGet("AnyScheme", TokenHandler).RequireAuthorization();
app.MapGet("Onlyjwt1", TokenHandler).RequireAuthorization("OnlyJWT1");
app.MapGet("OnlyjwtWithAdminRole", TokenHandler).RequireAuthorization("OnlyAdminRole");
app.MapGet("Onlyjwt2", TokenHandler).RequireAuthorization("OnlyJWT2");
app.MapGet("OnlyjwtEndpoints", TokenHandler).RequireAuthorization("OnlyJWT1","OnlyJWT2");
app.MapGet("OnlyCookie", TokenHandler).RequireAuthorization("OnlyCookie");
```

### Policies are setup as shown below 
```
builder.Services.AddAuthorization(op =>
{
    var defaultAuthPolicy = new AuthorizationPolicyBuilder(
        "MyCookieScheme", "Jwt1", "Jwt2"
    ).RequireAuthenticatedUser().Build();

    op.DefaultPolicy = defaultAuthPolicy;
    op.AddPolicy("OnlyJWT2", new AuthorizationPolicyBuilder("Jwt2").RequireAuthenticatedUser().Build());
    op.AddPolicy("OnlyAdminRole", new AuthorizationPolicyBuilder("Jwt2").RequireRole("Reader").RequireRole("Admin").RequireAuthenticatedUser().Build());
    op.AddPolicy("OnlyJWT1", new AuthorizationPolicyBuilder("Jwt1").RequireAuthenticatedUser().Build());
    op.AddPolicy("OnlyCookie", new AuthorizationPolicyBuilder("MyCookieScheme").RequireAuthenticatedUser().Build());
});
```


Checkout - https://github.com/Anish407/AuthorizeUsingMultipleSchemes/blob/master/MutlipleAuthSchemes.Api/Program.cs#L115
