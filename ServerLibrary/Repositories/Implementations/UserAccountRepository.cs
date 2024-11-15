using BaseLibrary.DTOs;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Constants = ServerLibrary.Helpers.Constants;

namespace ServerLibrary.Repositories.Implementations
{
    public class UserAccountRepository(IOptions<JwtSectoion> config, AppDbContext appDbContext) : IUserAccount
    {
        public async Task<GeneralResponse> CreateAsync(Register user)
        {
            if (user is null) return new GeneralResponse(false, "Model is Empty");

               var checkUser = await FindUserByEmail(user.Email);
            if (checkUser != null) return new GeneralResponse(false, "User registered already");
             
            //Save user
            var applicationUser = await AddToDatabase(new  ApplicationUser ()
            {
               Fullname = user.FullName,
               Email = user.Email,
               Password = BCrypt.Net.BCrypt.HashPassword(user.Password)
            });

            //check, create and assign role
            var checkAdminRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.Admin));
            if (checkAdminRole is null)
            {
                var createAdminRole = await AddToDatabase(new SystemRole() { Name = Constants.Admin });
                await AddToDatabase(new UserRole () { RoleId = createAdminRole.Id, UserId = applicationUser.Id });
                return new GeneralResponse(true, "Acount created");            
            }

            var checkUserRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(_=>_.Name!.Equals(Constants.User));
            SystemRole response = new();
            if (checkUserRole is null)
            {
                response = await AddToDatabase(new SystemRole() { Name = Constants.User });
                await AddToDatabase(new UserRole() { RoleId = response.Id, UserId = applicationUser.Id });
            }
            else
            {
                await AddToDatabase(new UserRole() { RoleId = checkAdminRole.Id, UserId = applicationUser.Id });
            }
            return new GeneralResponse(true, "Account Created");
        }
        // Vision 1, That is not working
        /*public async Task<LoginResponse> SignInAsync(Login user)
        {
            if (user is null) return new LoginResponse(false, "Model is empty");
            
            var applicationUser =  await FindUserByEmail(user.Email!);
            if (applicationUser is null) return new LoginResponse(false, "User not found");

            //Verify password
            if (!BCrypt.Net.BCrypt.Verify(user.Password, applicationUser.Password))
                return new LoginResponse(false, "Email/Password not valid");
            
            var getUserRole = await FindUserRole(applicationUser.Id);
            if (getUserRole is null) return new LoginResponse(false, "user role not found");

            var getRoleName = await FindRoleName(getUserRole.RoleId);
            if (getRoleName is null) return new LoginResponse(false, "user role not fount");


            string jwtToken = GenerateToken(applicationUser, getRoleName!.Name!);
            string refreshToken = GenerateRefreshToken();

            //Save the refresh token to database
            var findUser = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(r => r.UserId == applicationUser.Id);
            if (findUser is null)
            {
                findUser!.Token = refreshToken;
                await appDbContext.SaveChangesAsync();
            }
            else
            {
                await AddToDatabase(new RefreshTokenInfo() { Token = refreshToken, UserId = applicationUser.Id });
            }

            return new LoginResponse(true, "Login successfully", jwtToken, refreshToken);

        }

        private string GenerateToken(ApplicationUser user, string role)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Value.Key!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var userClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Fullname!),
                new Claim(ClaimTypes.Email, user.Email!),
                new Claim(ClaimTypes.Role, role!)
            };

            var token = new JwtSecurityToken(
                issuer: config.Value.Issuer,
                audience: config.Value.Audience,
                claims: userClaims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: credentials
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private async Task<UserRole> FindUserRole(int userId) => await appDbContext.UserRoles.FirstOrDefaultAsync(_ => _.UserId == userId);
        private async Task<SystemRole> FindRoleName(int roleId) => await appDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Id == roleId);

        private static string GenerateRefreshToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

        private async Task<ApplicationUser> FindUserByEmail(string email) =>
            await appDbContext.ApplicationUsers.FirstOrDefaultAsync(_ => _.Email!.ToLower()!.Equals(email!.ToLower()));

        private async Task<T> AddToDatabase<T>(T model)
        {
            var result = appDbContext.Add(model!);
            await appDbContext.SaveChangesAsync();
            return (T)result.Entity;
        }*/

        //Vision 2, That is working

        public async Task<LoginResponse> SignInAsync(Login user)
        {
            if (user == null) return new LoginResponse(false, "Model is empty");

            var applicationUser = await FindUserByEmail(user.Email!);
            if (applicationUser == null) return new LoginResponse(false, "User not found");

            // Verify password
            if (!BCrypt.Net.BCrypt.Verify(user.Password, applicationUser.Password))
                return new LoginResponse(false, "Email/Password not valid");

            // Get user role
            var getUserRole = await FindUserRole(applicationUser.Id);
            if (getUserRole == null) return new LoginResponse(false, "User role not found");

            // Get role name
            var getRoleName = await FindRoleName(getUserRole.RoleId);
            if (getRoleName == null || string.IsNullOrEmpty(getRoleName.Name))
                return new LoginResponse(false, "User role not found");

            // Generate tokens
            string jwtToken = GenerateToken(applicationUser, getRoleName.Name);
            string refreshToken = GenerateRefreshToken();

            //Save the refresh token to database
            var findUser = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.UserId == applicationUser.Id);
            if (findUser != null)
            {
                findUser.Token = refreshToken;
            }
            else
            {
                await AddToDatabase(new RefreshTokenInfo { Token = refreshToken, UserId = applicationUser.Id });
            }

            await appDbContext.SaveChangesAsync();

            return new LoginResponse(true, "Login successful", jwtToken, refreshToken);
        }

        private string GenerateToken(ApplicationUser user, string role)
        {
            if (string.IsNullOrEmpty(config.Value.Key) ||
                string.IsNullOrEmpty(config.Value.Issuer) ||
                string.IsNullOrEmpty(config.Value.Audience))
            {
                throw new ArgumentNullException("Configuration values for Key, Issuer, or Audience are missing.");
            }

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Value.Key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            // Check claims data
            if (user.Fullname == null || user.Email == null)
                throw new ArgumentNullException("User Fullname or Email cannot be null");

            var userClaims = new[]
            {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Fullname),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, role)
        };

            var token = new JwtSecurityToken(
                issuer: config.Value.Issuer,
                audience: config.Value.Audience,
                claims: userClaims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        private async Task<UserRole> FindUserRole(int userId) => await appDbContext.UserRoles.FirstOrDefaultAsync(r => r.UserId == userId);
        private async Task<SystemRole> FindRoleName(int roleId) => await appDbContext.SystemRoles.FirstOrDefaultAsync(r => r.Id == roleId);

        private static string GenerateRefreshToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

        private async Task<ApplicationUser> FindUserByEmail(string email) =>
            await appDbContext.ApplicationUsers.FirstOrDefaultAsync(u => u.Email!.ToLower() == email.ToLower());

        private async Task<T> AddToDatabase<T>(T model)
        {
            var result = appDbContext.Add(model!);
            await appDbContext.SaveChangesAsync();
            return (T)result.Entity;
        }


        public async Task<LoginResponse> RefreshTokenAsync(RefreshToken token)
        {
            if (token is null) return new LoginResponse(false, "Model is empty");

            var findToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.Token == token.Token);
            if (findToken is null) return new LoginResponse(false, "Refresh token not found or expired");

            // Retrieve user details associated with the refresh token
            var user = await appDbContext.ApplicationUsers.FirstOrDefaultAsync(u => u.Id == findToken.UserId);
            if (user is null) return new LoginResponse(false, "User not found for refresh token");

            var userRole = await FindUserRole(user.Id);
            if (userRole == null) return new LoginResponse(false, "User role not found");

            var roleName = await FindRoleName(userRole.RoleId);
            if (string.IsNullOrEmpty(roleName?.Name)) return new LoginResponse(false, "Role name not found");

            // Generate new tokens
            string newJwtToken = GenerateToken(user, roleName.Name);
            string newRefreshToken = GenerateRefreshToken();

            // Update the refresh token in the database
            findToken.Token = newRefreshToken;
            await appDbContext.SaveChangesAsync();

            return new LoginResponse(true, "Token refreshed successfully", newJwtToken, newRefreshToken);
        }

    }
}
  