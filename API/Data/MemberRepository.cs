using System;
using APi.Helpers;
using API.Entities;
using API.Helpers;
using API.interfaces;
using Microsoft.EntityFrameworkCore;

namespace API.Data;

public class MemberRepository(AppDbContext context) : IMemberRepository
{
    public async Task<Member?> GetMemberByIdAsync(string id)
    {
        return await context.Members.FindAsync(id);
    }

    public async Task<PaginatedResult<Member>> GetMembersAsync(MemberParams memberParams)
    {
        var query = context.Members.AsQueryable();
        query = query.Where(x => x.Id != memberParams.currentMemberId);
        
        if(memberParams.Gender != null)
        {
            query.Where(x => x.Gender == memberParams.Gender);
        }
        var minDob = DateOnly.FromDateTime(DateTime.Today.AddYears(-memberParams.MaxAge - 1));
        var maxDob = DateOnly.FromDateTime(DateTime.Today.AddYears(-memberParams.MinAge));

        query =  query.Where(x => x.DateOfBirth >= minDob && x.DateOfBirth <= maxDob);

        query = memberParams.OrderBy switch
        {
            "created" => query.OrderByDescending(x => x.Created),
            _ => query.OrderByDescending(x => x.LastActive)
        };

        return await PaginationHelper.CreateAsync(query, 
            memberParams.PageNumber, memberParams.pageSize);
    }

    public async Task<IReadOnlyList<Photo>> GetPhotosByMemberAsync(string memberId)
    {
        return await context.Members
                .Where(x => x.Id == memberId)
                .SelectMany(x => x.Photos)
                .ToListAsync();
    }

    public void Update(Member member)
    {
        context.Entry(member).State = EntityState.Modified;
    }

    public async Task<Member> GetMemberForUpdate(string id)
    {
        #pragma warning disable CS8603 // Possible null reference return.
        return await context.Members
                .Include(x => x.User)
                .Include(x => x.Photos)
                .SingleOrDefaultAsync(x => x.Id == id);
        #pragma warning restore CS8603 // Possible null reference return.
    }

}
