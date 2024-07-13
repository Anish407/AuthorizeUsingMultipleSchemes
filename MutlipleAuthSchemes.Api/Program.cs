using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Swashbuckle.AspNetCore.SwaggerUI;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
const string jwt1secret = "aV3ryS3cur3K3yTh4tIsAtLe4st32Byt3sLng";
const string Jwt2Secret = "ab3ryS3cur3K3yTh4tIsAtLe4st32Byt3sLng";

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddAuthentication()
    .AddCookie("MyCookieScheme")
    .AddJwtBearer("Jwt1", options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidIssuer = "myapi.com",
            ValidAudience = "myapi",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt1secret))
        };
    })
    .AddJwtBearer("Jwt2", options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidIssuer = "myapi.com",
            ValidAudience = "myapi2",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Jwt2Secret)),
        };
    });

builder.Services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
{
    options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
     
    };

    // for debugging auth events
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = (c) => {
            return Task.CompletedTask;        
        },

        OnChallenge = (c) => {
            return Task.CompletedTask;
        },

        OnForbidden = (context) => { 

            return Task.CompletedTask;
        },
        OnAuthenticationFailed = (context) =>
        {

            return Task.CompletedTask;
        }
    };
    //options.Audience = "web api's client id";
    //options.Authority = "https://login.microsoftonline.com/tenantid/v2.0";
});

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

WebApplication app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapPost("LoginWithCookie", Login).WithOpenApi();
app.MapGet("LoginWithJwt1", (HttpContext context) =>
{
    var token= GetBearerToken(jwtSecretKey: jwt1secret, schemeName: "Jwt1",  "myapi");
    return token;
});

app.MapGet("LoginWithJwt2", () =>
{
    // check username or password or authenticate in anyway
    return GetBearerToken(jwtSecretKey: Jwt2Secret, schemeName: "Jwt2", "myapi2");
});
app.MapPost("Hello", Dummy);
app.MapGet("AnyScheme", TokenHandler).RequireAuthorization();
app.MapGet("Onlyjwt1", TokenHandler).RequireAuthorization("OnlyJWT1");
app.MapGet("OnlyjwtWithAdminRole", TokenHandler).RequireAuthorization("OnlyAdminRole");
app.MapGet("Onlyjwt2", TokenHandler).RequireAuthorization("OnlyJWT2");
app.MapGet("OnlyjwtEndpoints", TokenHandler).RequireAuthorization("OnlyJWT1","OnlyJWT2");
app.MapGet("OnlyCookie", TokenHandler).RequireAuthorization("OnlyCookie");

app.Run();

static string Dummy()
{
    return "Dummy";
}

static async Task Login(HttpContext context)
{
    // Simulate user authentication (replace with your actual logic)

    var claims = new List<Claim>
    {
        new Claim("scheme", "Cookie"),
        new Claim("username", "Anish")
    };

    var claimsIdentity = new ClaimsIdentity(claims, "MyCookieScheme");
    var authProperties = new AuthenticationProperties
    {
        IsPersistent = true // Persist cookie across browser sessions
    };

    await context.SignInAsync(
        "MyCookieScheme",
        new ClaimsPrincipal(claimsIdentity),
        authProperties);

    context.Response.StatusCode = StatusCodes.Status200OK;
    await context.Response.WriteAsync("Authenticated successfully!");
}

string GetBearerToken(string jwtSecretKey,  string schemeName,string audience)
{
    // Convert the secret key to a byte array
    byte[] keyBytes = Encoding.UTF8.GetBytes(jwtSecretKey);

    // Ensure the secret key is of a valid length for HMACSHA256 (at least 256 bits/32 bytes)
    if (keyBytes.Length < 32)
    {
        throw new ArgumentException("Secret key must be at least 256 bits (32 bytes) in length.");
    }

    // Create the security key
    SymmetricSecurityKey securityKey = new SymmetricSecurityKey(keyBytes);

    // Create signing credentials using the security key and HMACSHA256 algorithm
    SigningCredentials credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
    

    // Define token descriptor
    JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(
        issuer: "myapi.com",
        audience: audience,
        claims: new[]
        {
            new Claim("scheme", schemeName),
            new Claim("username", "Anish"),
            new Claim("roles", "Admin"),
            new Claim("roles", "reader"),
            new Claim("roles", "writer"),
        },
        expires: DateTime.Now.AddMinutes(5),
        signingCredentials: credentials);

    // Generate the token
    string token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
    return token;
}



static Results<Ok<string>, NotFound> TokenHandler(HttpContext context)
{
    var scheme = context.User.Claims.FirstOrDefault(i => i.Type == "scheme");

    if (scheme is null || string.IsNullOrWhiteSpace(scheme.Value))
        return TypedResults.NotFound();

    return TypedResults.Ok(scheme.Value);
}