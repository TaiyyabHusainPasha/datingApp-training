using System;
using API.Entities;

namespace API.interfaces;

public interface IMemberRepository
{
    void Update(Member member);
    Task<bool> SaveAllAsync();
    Task<IReadOnlyList<Member>> GetMembersAsync();
    Task<Member?> GetMemberByIdAsync(string id);
    Task<IReadOnlyList<Photo>> GetPhotosByMemberAsync(string memberId);
    Task<Member> GetMemberForUpdate(string id);
}
