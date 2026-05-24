using APi.Helpers;

namespace API.Helpers;
public class MemberParams : PaginParams
{
    public string? Gender { get; set; }
    public string? currentMemberId { get; set; }
    public int MinAge { get; set; } = 18;
    public int MaxAge { get; set; } = 100;
    public string OrderBy { get; set; } = "lastActive";
}