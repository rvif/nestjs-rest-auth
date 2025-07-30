import {
    BadRequestException,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { DatabaseService } from 'src/database/database.service';
import { SignUpDto } from './dtos/signup.dto';
import * as bcrypt from 'bcrypt';
import { LoginDTO } from './dtos/login.dto';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import { RefreshTokenDto } from './dtos/refresh-token.dto';

@Injectable()
export class AuthService
{
    constructor(
        private readonly databaseService: DatabaseService,
        private jwtService: JwtService,
    )
    {}

    async signup(signUpData: SignUpDto)
    {
        const { name, email, password } = signUpData;
        // Check if email is in use
        const emailInUse = await this.databaseService.user.findUnique({
            where: {
                email,
            },
        });

        if (emailInUse)
        {
            throw new BadRequestException('Email already in use');
        }
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user and save to db
        await this.databaseService.user.create({
            data: { name, email, password: hashedPassword },
        });
    }

    async login(credentials: LoginDTO)
    {
        const { email, password } = credentials;
        // Find if user exists by email
        const user = await this.databaseService.user.findUnique({
            where: {
                email,
            },
        });

        if (!user)
        {
            throw new UnauthorizedException('Wrong credentials');
        }
        // Compare entered password with existing password
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch)
        {
            throw new UnauthorizedException('Wrong credentials');
        }

        // Generate JWT tokens
        return this.generateUserTokens(user.id);
    }

    async refreshTokens(refreshTokenDto: RefreshTokenDto)
    {
        const { refreshToken } = refreshTokenDto;
        // TODO: Verify refresh token exists and hasn't expired
        const token = await this.databaseService.refreshToken.findUnique({
            where: {
                token: refreshToken,
            },
        });

        if (!token || token.expiryDate < new Date())
        {
            // redirect user to login page on the frontend
            throw new UnauthorizedException('Refresh Token is invalid');
        }
        // TODO: Obtain userId from that refresh token, and generateUserTokens
        await this.databaseService.refreshToken.delete({
            where: {
                token: refreshToken,
            },
        });
        return this.generateUserTokens(token.userId);
        // TODO: Delete old refreshToken and save the new to db
    }

    async generateUserTokens(userId)
    {
        const accessToken = this.jwtService.sign(
            { userId },
            { expiresIn: '1h' },
        );

        const refreshToken = uuidv4();

        await this.storeRefreshToken(refreshToken, userId);

        return {
            accessToken,
            refreshToken,
        };
    }

    async storeRefreshToken(token: string, userId: string)
    {
        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + 3);
        await this.databaseService.refreshToken.upsert({
            where: {
                userId,
            },
            update: {
                token,
                expiryDate,
            },
            create: {
                token,
                userId,
                expiryDate,
            },
        });
    }
}
