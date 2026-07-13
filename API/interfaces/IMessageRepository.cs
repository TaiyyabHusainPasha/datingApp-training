using APi.Helpers;
using API.DTOs;
using API.Entities;
using API.Helpers;

namespace API.interfaces
{
    public interface IMessageRepository
    {
        void AddMessage(Message message);
        void DeleteMessage(Message message);

        Task<Message?> GetMessage(string messageId);
        Task<PaginatedResult<MessageDto>> GetMessageForMember(MessageParams messageParams);
        Task<IReadOnlyList<MessageDto>> GetMessageThread(string currentMemberId, string recipientId);
        Task<bool> SaveAllAsync();



    }
}
