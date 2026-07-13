
using API.Entities;

namespace API.interfaces;

public interface ITokenService
{
    Task<string> CreateToken(AppUser user);
    string GenerateRefereshToken();
}
