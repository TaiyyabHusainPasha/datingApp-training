using API.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AdminController(UserManager<AppUser> userManager) : BaseApiController
    {
        [Authorize(Policy ="RequiredAdminRole")]
        [HttpGet("users-with-roles")]
        public async Task<ActionResult> GetUsersWithRoles()
        {
            var users = await userManager.Users.ToListAsync();
            var userList = new List<Object>();
            foreach (var user in users)
            {
                var roles = await userManager.GetRolesAsync(user);
                userList.Add(new
                {
                    user.Id,
                    user.Email,
                    Roles = roles.ToList()
                });
            }
           return Ok(userList);
        }


        [Authorize(Policy = "RequiredAdminRole")]
        [HttpPost("edit-roles/{userId}")]
        public async Task<ActionResult> EditRoles(string userId, [FromQuery] string roles)
        {
            if (string.IsNullOrEmpty(roles)) return BadRequest("You must select atleast one role");

            var selectRoles = roles.Split(',').ToArray();

            var user = await userManager.FindByIdAsync(userId);

            if (user == null) return BadRequest("Could not retrieve user");

            var userRoles = await userManager.GetRolesAsync(user);

            var result = await userManager.AddToRolesAsync(user, selectRoles.Except(userRoles));

            if (!result.Succeeded) return BadRequest("Failed to add roles");

            result = await userManager.RemoveFromRolesAsync(user, userRoles.Except(userRoles));

            if (!result.Succeeded) return BadRequest("Failed to remove from roles");

            return Ok(await userManager.GetRolesAsync(user));

        }

        [Authorize(Policy = "ModeratePhotoRoles")]
        [HttpGet("photos-to-moderate")]
        public ActionResult GetPhotosForMaderation()
        {
            return Ok("Admins or moderators can see this");
        }
    }
}
