using System;
using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Extensions;
using API.interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;

public class AccountController : BaseApiController
{
    private readonly UserManager<AppUser> _userManager;
    private readonly ITokenService _tokenService;
    public AccountController(UserManager<AppUser> userManager, ITokenService tokenService)
    {
        _userManager = userManager;
        _tokenService = tokenService;
    }

    [HttpPost("register")]
    public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
    {
        DateOnly dob;
        DateOnly.TryParse(registerDto.DateOfBirth, out dob);

        var user = new AppUser
        {
            DisplayName = registerDto.DisplayName,
            Email = registerDto.Email,
            UserName = registerDto.Email,
            Member = new Member
            {
                City = registerDto.City,
                Country = registerDto.Country,
                DisplayName = registerDto.DisplayName,
                Gender = registerDto.Gender,
                DateOfBirth = dob
            }
        };

        var result = await _userManager.CreateAsync(user, registerDto.Password);
        if (!result.Succeeded)
        {
            foreach (var item in result.Errors)
            {
                ModelState.AddModelError("identity", item.Description);
            }
            return ValidationProblem();
        }

        await _userManager.AddToRoleAsync(user, "Member");

        await SetRefereshTokenCookie(user);

        return await user.ToDto(_tokenService);
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
    public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
    {
        var user = await _userManager.FindByEmailAsync(loginDto.Email);

        if (user == null)
            return Unauthorized("Invalid email address");

        var result = await _userManager.CheckPasswordAsync(user, loginDto.Password);

        if (!result)
            return Unauthorized("Invalid password");

        await SetRefereshTokenCookie(user);

        return await user.ToDto(_tokenService);
    }

    [HttpPost("refresh-token")]
    public async Task<ActionResult<UserDto>> RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        if (refreshToken == null) return NoContent();
        var user = await _userManager.Users.FirstOrDefaultAsync(x => x.RefreshToken == refreshToken &&
            x.RefreshTokenExpiry > DateTime.UtcNow);
        if (user == null) return Unauthorized();

        await SetRefereshTokenCookie(user);

        return await user.ToDto(_tokenService);

    }

    private async Task SetRefereshTokenCookie(AppUser user)
    {
        var refershToken = _tokenService.GenerateRefereshToken();
        user.RefreshToken = refershToken;
        user.RefreshTokenExpiry = DateTime.Now.AddDays(7);
        await _userManager.UpdateAsync(user);

        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.Now.AddDays(7)
        };
        Response.Cookies.Append("refreshToken", refershToken, cookieOptions);
    }

}
