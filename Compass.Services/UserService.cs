using AutoMapper;
using Compass.Data.Data.Interfaces;
using Compass.Data.Data.Models;
using Compass.Data.Data.ViewModels;
using Compass.Services.Configuration;
using Microsoft.AspNet.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Globalization;
using System.Text;

namespace Compass.Services
{
    public class UserService
    {
        private readonly IUserRepository _userRepository;
        private IConfiguration _configuration;
        private EmailService _emailService;
        private JwtService _jwtService;
        private readonly IMapper _mapper;

        public UserService(IUserRepository userRepository, JwtService jwtService, IConfiguration configuration, EmailService emailService, IMapper mapper, IOptionsMonitor<JwtConfig> optionsMonitor, TokenValidationParameters tokenValidationParameters)
        {
            _userRepository = userRepository;
            _configuration = configuration;
            _emailService = emailService;
            _jwtService = jwtService;
            _mapper = mapper;
        }
        public async Task<ServiceResponse> RegisterUserAsync(RegisterUserVM model)
        {
            if (model == null)
            {
                throw new NullReferenceException("Register model is null.");
            }

            if (model.Password != model.ConfirmPassword)
            {
                return new ServiceResponse
                {
                    Message = "Confirm pssword do not match",
                    IsSuccess = false
                };
            }

            var newUser = _mapper.Map<RegisterUserVM, AppUser>(model);

            var result = await _userRepository.RegisterUserAsync(newUser, model.Password);
            if (result.Succeeded)
            {
                await _userRepository.AddUserToRoleAsync(newUser, model.Role);
                var token = await _userRepository.GenerateEmailConfirmationTokenAsync(newUser);

                var encodedEmailToken = Encoding.UTF8.GetBytes(token);
                var validEmailToken = WebEncoders.Base64UrlEncode(encodedEmailToken);

                string url = $"{_configuration["HostSettings:URL"]}/api/User/confirmemail?userid={newUser.Id}&token={validEmailToken}";

                string emailBody = $"<h1>Confirm your email</h1> <a href='{url}'>Confirm now</a>";
                await _emailService.SendEmailAsync(newUser.Email, "Email confirmation.", emailBody);

                var tokens = await _jwtService.GenerateJwtTokenAsync(newUser);

                return new ServiceResponse
                {
                    AccessToken = tokens.token,
                    RefreshToken = tokens.refreshToken.Token,
                    Message = "User successfully created.",
                    IsSuccess = true
                };
            }
            else
            {
                return new ServiceResponse
                {
                    Message = "Error user not created.",
                    IsSuccess = false,
                    Errors = result.Errors.Select(e => e.Description)
                };
            }
        }

        public async Task<ServiceResponse> LoginUserAsync(LoginUserVM model)
        {
            var user = await _userRepository.GetUserByEmailAsync(model.Email);

            if (user == null)
            {
                return new ServiceResponse
                {
                    Message = "Login or password incorrect.",
                    IsSuccess = false
                };
            }

            var loginResult = await _userRepository.LoginUserAsync(user, model.Password, model.RememberMe);

            if (loginResult.Succeeded)
            {
                var tokens = await _jwtService.GenerateJwtTokenAsync(user);

                return new ServiceResponse
                {
                    AccessToken = tokens.token,
                    RefreshToken = tokens.refreshToken.Token,
                    Message = "Logged in successfully",
                    IsSuccess = true,
                };
            }
            else if(loginResult.IsNotAllowed)
            {
                return new ServiceResponse
                {
                    Message = "Email not confirmed",
                    IsSuccess = false,
                };
            }
            else if(loginResult.IsLockedOut)
            {
                return new ServiceResponse
                {
                    Message = "More than 5 attempts",
                    IsSuccess = false,
                };
            }
            else
            {
                return new ServiceResponse
                {
                    Message = "Login or password incorrect.",
                    IsSuccess = false
                };
            }
        }

        public async Task<ServiceResponse> ConfirmEmailAsync(string userId, string token)
        {
            var user = await _userRepository.GetUserByIdAsync(userId);
            if (user == null)
                return new ServiceResponse
                {
                    IsSuccess = false,
                    Message = "User not found"
                };

            var decodedToken = WebEncoders.Base64UrlDecode(token);
            string normalToken = Encoding.UTF8.GetString(decodedToken);

            var result = await _userRepository.ConfirmEmailAsync(user, normalToken);

            if (result.Succeeded)
                return new ServiceResponse
                {
                    Message = "Email confirmed successfully!",
                    IsSuccess = true,
                };

            return new ServiceResponse
            {
                IsSuccess = false,
                Message = "Email did not confirm",
                Errors = result.Errors.Select(e => e.Description)
            };
        }

        public async Task<ServiceResponse> ForgotPasswordAsync(string email)
        {
            var user = await _userRepository.GetUserByEmailAsync(email);
            if (user == null)
            {
                return new ServiceResponse
                {
                    Message = "No user associated with email",
                    IsSuccess = false
                };
            }

            var token = await _userRepository.GeneratePasswordResetTokenAsync(user);
            var encodedToken = Encoding.UTF8.GetBytes(token);
            var validToken = WebEncoders.Base64UrlEncode(encodedToken);

            string url = $"{_configuration["HostSettings:URL"]}/ResetPassword?email={email}&token={validToken}";
            string emailBody = "<h1>Follow the instructions to reset your password</h1>" + $"<p>To reset your password <a href='{url}'>Click here</a></p>";
            await _emailService.SendEmailAsync(email, "Fogot password", emailBody);

            return new ServiceResponse
            {
                IsSuccess = true,
                Message = $"Reset password for {_configuration["HostSettings:URL"]} has been sent to the email successfully!"
            };
        }

        public async Task<ServiceResponse> ResetPasswordAsync(ResetPasswordVM model)
        {
            var user = await _userRepository.GetUserByEmailAsync(model.Email);
            if (user == null)
            {
                return new ServiceResponse
                {
                    IsSuccess = false,
                    Message = "No user associated with email",
                };
            }

            if (model.NewPassword != model.ConfirmPassword)
            {
                return new ServiceResponse
                {
                    IsSuccess = false,
                    Message = "Password doesn't match its confirmation",
                };
            }

            var decodedToken = WebEncoders.Base64UrlDecode(model.Token);
            string normalToken = Encoding.UTF8.GetString(decodedToken);

            var result = await _userRepository.ResetPasswordAsync(user, normalToken, model.NewPassword);
            if (result.Succeeded)
            {
                return new ServiceResponse
                {
                    Message = "Password has been reset successfully!",
                    IsSuccess = true,
                };
            }
            return new ServiceResponse
            {
                Message = "Something went wrong",
                IsSuccess = false,
                Errors = result.Errors.Select(e => e.Description),
            };
        }

        public async Task<ServiceResponse> RefreshTokenAsync(TokenRequestVM model)
        {
            var result = await _jwtService.VerifyTokenAsync(model);
            if (result == null)
            {
                return result;
            }
            else
            {
                return result;
            }
        }

        public async Task<ServiceResponse> GetAllUsersAsync()
        {
            var users = await _userRepository.GetAllUsersAsync();
            var usersVM = new List<AllUsersVM>();

            foreach (var user in users)
            {
                var userVM = _mapper.Map<AllUsersVM>(user);
                var roles = await _userRepository.GetRolesAsync(user);
                userVM.Role = roles.First();
                usersVM.Add(userVM);
            }

            return new ServiceResponse
            {
                Message = "All users successfully loaded.",
                IsSuccess = true,
                Payload = usersVM
            };
        }

        public async Task<ServiceResponse> GetRolesAsync()
        {
            var roles = await _userRepository.GetAllRolesAsync();
            var rolesName = roles.Select(r => r.Name).ToList();

            return new ServiceResponse
            {
                IsSuccess = true,
                Message = "Roles loaded",
                Payload = rolesName
            };
        }

        public async Task<ServiceResponse> UpdateUserProfileAsync(UserProfile model)
        {
            var user = await _userRepository.GetUserByIdAsync(model.Id);
            user.Name = model.Name;
            user.Surname = model.Surname;
            user.PhoneNumber = model.PhoneNumber;

            var result = await _userRepository.UpdateUserAsync(user);

            if (result.Succeeded)
            {
                var tokens = await _jwtService.GenerateJwtTokenAsync(user);

                return new ServiceResponse
                {
                    AccessToken = tokens.token,
                    RefreshToken = tokens.refreshToken.Token,
                    Message = "Profile updated",
                    IsSuccess = true,
                };
            }
            else
            {
                return new ServiceResponse
                {
                    IsSuccess = false,
                    Message = "Profile not updated",
                    Errors = result.Errors.Select(e => e.Description)
                };
            }
        }

        public async Task<ServiceResponse> ChangePasswordAsync(ChangePasswordVM model)
        {
            var user = await _userRepository.GetUserByIdAsync(model.Id);
            var result = await _userRepository.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
            var errors = result.Errors.Select(e => e.Description).ToList();
            var error = errors.Count > 0 ? errors.FirstOrDefault() : "Password has not been changed";

            if (result.Succeeded)
            {
                return new ServiceResponse
                {
                    Message = "Password successfully changed",
                    IsSuccess = true,
                };
            }
            else
            {
                return new ServiceResponse
                {
                    IsSuccess = false,
                    Message = error,
                    Errors = errors
                };
            }
        }

        public async Task<ServiceResponse> EditUserAsync(EditUserVM model)
        {
            var user = await _userRepository.GetUserByIdAsync(model.Id);

            if (user.Email != model.Email)
            {
                var emailResult = await _userRepository.ChangeEmailAsync(user, model.Email, model.token);
                if (!emailResult.Succeeded)
                {
                    var emailErrors = emailResult.Errors.Select(e => e.Description).ToList();
                    var emailError = emailErrors.Count > 0 ? emailErrors.FirstOrDefault() : "Email not changed";
                    return new ServiceResponse
                    {
                        Message = emailError,
                        IsSuccess = false,
                        Errors = emailErrors
                    };
                }
            }

            var roleResult = await _userRepository.ChangeRoleAsync(user, model.role);
            if (!roleResult.Succeeded)
            {
                var roleErrors = roleResult.Errors.Select(e => e.Description).ToList();
                var roleError = roleErrors.Count > 0 ? roleErrors.FirstOrDefault() : "Role not changed";
                return new ServiceResponse
                {
                    Message = roleError,
                    IsSuccess = false,
                    Errors = roleErrors
                };
            }

            user.Name = model.Name;
            user.Surname = model.Surname;
            user.PhoneNumber = model.PhoneNumber;

            var result = await _userRepository.UpdateUserAsync(user);

            if (result.Succeeded)
            {
                return new ServiceResponse
                {
                    Message = "User information updated",
                    IsSuccess = true
                };
            }

            var errors = result.Errors.Select(e => e.Description).ToList();
            var error = errors.Count > 0 ? errors.FirstOrDefault() : "User not updated";
            return new ServiceResponse
            {
                Message = error,
                IsSuccess = false,
                Errors = errors
            };
        }

        public async Task<ServiceResponse> DeleteUserAsync(string id)
        {
            var user = await _userRepository.GetUserByIdAsync(id);
            var result = await _userRepository.DeleteUserAsync(user);
            if(result.Succeeded)
            {
                return new ServiceResponse
                {
                    IsSuccess = true,
                    Message = "User deleted success"
                };
            }
            else
            {
                return new ServiceResponse
                {
                    IsSuccess = false,
                    Message = "User not deleted"
                };
            }
        }

        public async Task<ServiceResponse> LockUserAsync(string id)
        {
            var user = await _userRepository.GetUserByIdAsync(id);
            if(user.LockoutEnabled)
            {
                var result = await _userRepository.UnlockUserAsync(user);

                if(result.Succeeded)
                {
                    return new ServiceResponse
                    {
                        IsSuccess = true,
                        Message = "User unblocked"
                    };
                }
                else
                {
                    return new ServiceResponse
                    {
                        IsSuccess = false,
                        Message = "User not unblocked"
                    };
                }
            }
            else
            {
                var result = await _userRepository.LockUserAsync(user);

                if (result.Succeeded)
                {
                    return new ServiceResponse
                    {
                        IsSuccess = true,
                        Message = "User blocked"
                    };
                }
                else
                {
                    return new ServiceResponse
                    {
                        IsSuccess = false,
                        Message = "User not blocked"
                    };
                }
            }
        }
    }
}
