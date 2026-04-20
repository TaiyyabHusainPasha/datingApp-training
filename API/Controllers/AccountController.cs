using System;
using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Extensions;
using API.interfaces;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers;

public class AccountController : BaseApiController
{
    private readonly AppDbContext _context;
    private readonly ITokenService _tokenService;
    public AccountController(AppDbContext context, ITokenService tokenService)
    {
        _context = context;
        _tokenService = tokenService;
    }

    [HttpPost("register")]
    public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
    {
        if (await EmailExists(registerDto.Email)) return BadRequest("Email taken");
        using var hmac = new HMACSHA512();
        var user = new AppUser
        {   
            DisplayName = registerDto.DisplayName,
            Email = registerDto.Email,
            PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
            PasswordSalt = hmac.Key
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
       return user.ToDto(_tokenService);
    }

    // [HttpPost("login")]
    // public async Task<ActionResult<AppUser>> Login(LoginDto loginDto){
    //     var user =  _context.Users.SingleOrDefault(x =>x.Email == loginDto.Email);
    //                 if(user == null) return Unauthorized("Invalid email address");
    //     using var hmac = new HMACSHA512(user.PasswordSalt);
    //     var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));
    //     for(int i = 0; i < computedHash.Length; i++)
    //     {
    //         if(computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid password");
    //     }
    //     return user;

    // }

        [HttpPost("login")]
    public async Task<ActionResult<UserDto>> Login(LoginDto loginDto){
        var user =  _context.Users.SingleOrDefault(x =>x.Email == loginDto.Email);
                    if(user == null) return Unauthorized("Invalid email address");
     
    return user.ToDto(_tokenService);


    }
    private async Task<bool> EmailExists(string email)
    {
        return _context.Users.Any(x =>x.Email.ToLower() == email.ToLower());
    }

}
