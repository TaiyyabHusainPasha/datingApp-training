using API.Data;
using API.Entities;
using API.interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    [Authorize]
    public class MembersController(IMemberRepository memberRepository) : BaseApiController
    {
        [HttpGet]
        public async Task<ActionResult<IReadOnlyList<Member>>> getMembers()
        {
            return Ok(await memberRepository.GetMembersAsync());
        }
        
        
        [HttpGet("{id}")]
        public async Task<ActionResult<Member>> getMember(string id)
        {
            var member = await memberRepository.GetMemberByIdAsync(id);
            if(member == null) return NotFound();
            return member;
        }

        [HttpGet("{id}/photos")]
        public async Task<ActionResult<IReadOnlyList<Photo>>> GetMemberPhoto(string id)
        {
            return Ok(await memberRepository.GetPhotosByMemberAsync(id));
        }

    }
}
