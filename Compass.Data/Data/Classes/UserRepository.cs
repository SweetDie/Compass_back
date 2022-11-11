using Compass.Data.Data.Context;
using Compass.Data.Data.Interfaces;
using Compass.Data.Data.Models;
using Compass.Data.Data.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Compass.Data.Data.Classes
{
    public class UserRepository : IUserRepository
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;

        public UserRepository(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public async Task<SignInResult> LoginUserAsync(AppUser model, string password, bool rememberMe)
        {
            var result = await _signInManager.PasswordSignInAsync(model, password, rememberMe, true);
            return result;
        }

        public async Task<IdentityResult> RegisterUserAsync(AppUser model, string password)
        {
            var result = await _userManager.CreateAsync(model, password);
            return result;
        }

        public async Task<bool> ValidatePasswordAsync(AppUser model, string password)
        {
            var result = await _userManager.CheckPasswordAsync(model, password);
            return result;
        }

        public async Task<string> GenerateEmailConfirmationTokenAsync(AppUser appUser)
        {
            var result = await _userManager.GenerateEmailConfirmationTokenAsync(appUser);
            return result;
        }

        public async Task<AppUser> GetUserByIdAsync(string id)
        {
            var result = await _userManager.FindByIdAsync(id);
            return result;
        }

        public async Task<IdentityResult> ConfirmEmailAsync(AppUser model, string token)
        {
            var result = await _userManager.ConfirmEmailAsync(model, token);
            return result;
        }

        public async Task<AppUser> GetUserByEmailAsync(string email)
        {
            var result = await _userManager.FindByEmailAsync(email);
            return result;
        }

        public async Task<string> GeneratePasswordResetTokenAsync(AppUser model)
        {
            var result = await _userManager.GeneratePasswordResetTokenAsync(model);
            return result;
        }

        public async Task<IdentityResult> ResetPasswordAsync(AppUser model, string token, string password)
        {
            var result = await _userManager.ResetPasswordAsync(model, token, password);
            return result;
        }

        public async Task SaveRefreshTokenAsync(RefreshToken refreshToken)
        {
            using (var _context = new AppDbContext())
            {
                await _context.RefreshTokens.AddAsync(refreshToken);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<RefreshToken> CheckRefreshTokenAsync(string refreshToken)
        {
            using (var _context = new AppDbContext())
            {
                var result = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == refreshToken);
                return result;
            }
        }

        public async Task UpdateRefreshTokenAsync(RefreshToken refreshToken)
        {
            using (var _context = new AppDbContext())
            {
                _context.RefreshTokens.Update(refreshToken);
                await _context.SaveChangesAsync();
            }
        }

        async Task<IList<string>> IUserRepository.GetRolesAsync(AppUser model)
        {
            var result = await _userManager.GetRolesAsync(model);
            return result;
        }

        public async Task<List<AppUser>> GetAllUsersAsync()
        {
            var result = await _userManager.Users.ToListAsync();
            return result;
        }

        public async Task<List<IdentityRole>> GetAllRolesAsync()
        {
            var _context = new AppDbContext();
            var roles = await _context.Roles.ToListAsync();
            _context.DisposeAsync();
            return roles;
        }

        public async Task<IdentityResult> AddUserToRoleAsync(AppUser model, string role)
        {
            var result = await _userManager.AddToRoleAsync(model, role);
            return result;
        }

        public async Task<IdentityResult> UpdateUserAsync(AppUser model)
        {
            var result = await _userManager.UpdateAsync(model);
            return result;
        }

        public async Task<IdentityResult> ChangePasswordAsync(AppUser model, string currentPassword, string newPassword)
        {
            var result = await _userManager.ChangePasswordAsync(model, currentPassword, newPassword);
            return result;
        }

        public async Task<IdentityResult> ChangeEmailAsync(AppUser model, string newEmail, string token)
        {
            var result = await _userManager.ChangeEmailAsync(model, newEmail, token);
            return result;
        }

        public async Task<IdentityResult> ChangeRoleAsync(AppUser model, string role)
        {
            var isInRole = await _userManager.IsInRoleAsync(model, role);
            if (isInRole)
            {
                return IdentityResult.Success;
            }
            else
            {
                var roles = await GetAllRolesAsync();
                await _userManager.RemoveFromRolesAsync(model, roles.Select(r => r.Name));
                return await AddUserToRoleAsync(model, role);
            }
        }

        public async Task<IdentityResult> LockUserAsync(AppUser model)
        {
            var result = await _userManager.SetLockoutEnabledAsync(model, true);
            return result;
        }

        public async Task<IdentityResult> UnlockUserAsync(AppUser model)
        {
            var result = await _userManager.SetLockoutEnabledAsync(model, false);
            return result;
        }

        public async Task<IdentityResult> DeleteUserAsync(AppUser model)
        {
            var result = await _userManager.DeleteAsync(model);
            return result;
        }
    }
}
