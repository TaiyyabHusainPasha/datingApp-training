using APi.Helpers;
using API.Entities;
using API.interfaces;
using Microsoft.EntityFrameworkCore;

namespace API.Data;

public class LikeRepository(AppDbContext context) : ILikeRepository
{
    public void AddLike(MemberLike like)
    {
        context.Likes.Add(like);
    }

    public void DeleteLike(MemberLike like)
    {
        context.Likes.Remove(like);
    }

    public async Task<IReadOnlyList<string>> GetCurrentMemberLikeIds(string memberId)
    {
        return await context.Likes
                .Where(x => x.SourceMmberId == memberId)
                .Select(x => x.TargetMemberId)
                .ToListAsync();
    }

    public async Task<MemberLike?> GetMemberLike(string sourceMemberId, string targetMemberId)
    {
        return await context.Likes.FindAsync(sourceMemberId, targetMemberId);
    }

    public async Task<PaginatedResult<Member>> GetMemberLikes(LikesParams likesParams)
    {
        var query = context.Likes.AsQueryable();
        IQueryable<Member> result;

        switch (likesParams.Predicate)
        {
            case "liked":
                 result = query
                    .Where(like => like.SourceMmberId == likesParams.MemberId)
                    .Select(like => like.TargetMember);
                break;
            case "likeddBy":
                 result = query
                    .Where(like => like.TargetMemberId == likesParams.MemberId)
                    .Select(like => like.SourceMember);       
                    break;             
            default: //mutual
            var likeIds = await GetCurrentMemberLikeIds(likesParams.MemberId);

             result = query
                .Where(x => x.TargetMemberId == likesParams.MemberId 
                    && likeIds.Contains(x.SourceMmberId))
                .Select(x => x.SourceMember);
                break;
        }
        return await PaginationHelper.CreateAsync(result,
            likesParams.PageNumber, likesParams.pageSize);
    }

    public async Task<bool> SaveAllChanges()
    {
        return await context.SaveChangesAsync() > 0;
    }
}