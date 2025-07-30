import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from './dtos/signup.dto';
import { LoginDTO } from './dtos/login.dto';
import { RefreshTokenDto } from './dtos/refresh-token.dto';

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

    // Refresh Token
    @Post('refresh')
    async refreshTokens(@Body() refreshTokenDto: RefreshTokenDto)
    {
        return this.authService.refreshTokens(refreshTokenDto);
    }
}
