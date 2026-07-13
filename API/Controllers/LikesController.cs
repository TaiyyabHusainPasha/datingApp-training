using APi.Helpers;
using API.Entities;
using API.Extensions;
using API.interfaces;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers;

public class LikesController(ILikeRepository likeRepository): BaseApiController
{
    [HttpPost("{targetMemberId}")]
    public async Task<ActionResult> ToggleLike(string targetMemberId)
    {
        var sourceMemberId = User.GetMemberId();
        if(sourceMemberId == targetMemberId) return BadRequest("You can not like yourself!!");

        var existingLike = await likeRepository.GetMemberLike(sourceMemberId, targetMemberId);

        if(existingLike == null)
        {
            var like = new MemberLike
            {
                SourceMmberId = sourceMemberId,
                TargetMemberId = targetMemberId
            };
            likeRepository.AddLike(like);
        }
        else
        {
            likeRepository.DeleteLike(existingLike);
        }
        if(await likeRepository.SaveAllChanges()) return Ok();

        return BadRequest("Failed to update like");
    }
    [HttpGet("list")] 
    public async Task<ActionResult<IReadOnlyList<string>>> GetCurrentMemberLikeIds()
    {
        return Ok(await likeRepository.GetCurrentMemberLikeIds(User.GetMemberId()));
    }

    [HttpGet] 
    public async Task<ActionResult<PaginatedResult<Member>>> GetMemberLikes(
        [FromQuery] LikesParams likesParams)
    {
        likesParams.MemberId = User.GetMemberId();
        Console.WriteLine(likesParams.MemberId);
        var members = await likeRepository.GetMemberLikes(likesParams);
        Console.WriteLine("members: ", members);
        return Ok(members);
    }
}