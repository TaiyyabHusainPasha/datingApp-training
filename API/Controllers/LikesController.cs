using APi.Helpers;
using API.Entities;
using API.Extensions;
using API.interfaces;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers;

public class LikesController(IUnitOfWork uow): BaseApiController
{
    [HttpPost("{targetMemberId}")]
    public async Task<ActionResult> ToggleLike(string targetMemberId)
    {
        var sourceMemberId = User.GetMemberId();
        if(sourceMemberId == targetMemberId) return BadRequest("You can not like yourself!!");

        var existingLike = await uow.LikeRepository.GetMemberLike(sourceMemberId, targetMemberId);

        if(existingLike == null)
        {
            var like = new MemberLike
            {
                SourceMmberId = sourceMemberId,
                TargetMemberId = targetMemberId
            };
            uow.LikeRepository.AddLike(like);
        }
        else
        {
            uow.LikeRepository.DeleteLike(existingLike);
        }
        if(await uow.Complete()) return Ok();

        return BadRequest("Failed to update like");
    }
    [HttpGet("list")] 
    public async Task<ActionResult<IReadOnlyList<string>>> GetCurrentMemberLikeIds()
    {
        return Ok(await uow.LikeRepository.GetCurrentMemberLikeIds(User.GetMemberId()));
    }

    [HttpGet] 
    public async Task<ActionResult<PaginatedResult<Member>>> GetMemberLikes(
        [FromQuery] LikesParams likesParams)
    {
        likesParams.MemberId = User.GetMemberId();
        //Console.WriteLine(likesParams.MemberId);
        var members = await uow.LikeRepository.GetMemberLikes(likesParams);
        //Console.WriteLine("members: ", members);
        return Ok(members);
    }
}