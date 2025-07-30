import { Body, Controller, Patch, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from './dtos/signup.dto';
import { LoginDTO } from './dtos/login.dto';
import { RefreshTokenDto } from './dtos/refresh-token.dto';
import { AuthGuard } from 'src/guards/auth.guard';
import { ChangePasswordDto } from './dtos/change-password.dto';
import { ForgotPasswordDto } from './dtos/forgot-password.dto';
import { ResetPasswordDto } from './dtos/reset-password.dto';

@Controller('auth')
export class AuthController
{
    constructor(private readonly authService: AuthService)
    {}

    // POST Signup
    @Post('signup')
    async signUp(@Body() signUpData: SignUpDto)
    {
        return this.authService.signup(signUpData);
    }

    // POST Login
    @Post('login')
    async login(@Body() credentials: LoginDTO)
    {
        return this.authService.login(credentials);
    }

    // POST Refresh Token
    @Post('refresh')
    async refreshTokens(@Body() refreshTokenDto: RefreshTokenDto)
    {
        return this.authService.refreshTokens(refreshTokenDto);
    }

    // POST Change Password (user needs to be logged in)
    @UseGuards(AuthGuard)
    @Patch('change-password')
    async changePassword(
        @Req() req,
        @Body() changePasswordDto: ChangePasswordDto,
    )
    {
        return this.authService.changePassword(
            req.userId,
            changePasswordDto.oldPassword,
            changePasswordDto.newPassword,
        );
    }

    // POST Forgot Password (public api, sends email with reset password link)
    @Post('forgot-password')
    async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto)
    {
        return this.authService.forgotPassword(forgotPasswordDto);
    }

    // POST Reset Password
    @Patch('reset-password')
    async resetPassword(@Body() resetPasswordDto: ResetPasswordDto)
    {
        return this.authService.resetPassword(resetPasswordDto);
    }
}
