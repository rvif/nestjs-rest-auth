import {
    BadRequestException,
    Injectable,
    NotFoundException,
    UnauthorizedException,
} from '@nestjs/common';
import { DatabaseService } from 'src/database/database.service';
import { SignUpDto } from './dtos/signup.dto';
import * as bcrypt from 'bcrypt';
import { LoginDTO } from './dtos/login.dto';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import { RefreshTokenDto } from './dtos/refresh-token.dto';
import { NotFoundError } from 'rxjs';
import { ForgotPasswordDto } from './dtos/forgot-password.dto';
import { nanoid } from 'nanoid';
import { MailService } from 'src/services/mail.service';
import { ResetPasswordDto } from './dtos/reset-password.dto';

@Injectable()
export class AuthService
{
    constructor(
        private readonly databaseService: DatabaseService,
        private jwtService: JwtService,
        private mailService: MailService,
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

    async changePassword(userId, oldPassword: string, newPassword: string)
    {
        // Find the user
        const user = await this.databaseService.user.findUnique({
            where: {
                id: userId,
            },
        });

        if (!user)
        {
            throw new NotFoundException('User Not Found');
        }
        // Compare the old password with the stored password
        const passwordMatch = await bcrypt.compare(oldPassword, user.password);
        if (!passwordMatch)
        {
            throw new UnauthorizedException('Wrong credentials');
        }
        // Change the user's password (DON'T FORGET TO HASH IT)
        const newHashedPassword = await bcrypt.hash(newPassword, 10);

        await this.databaseService.user.update({
            where: {
                id: userId,
            },
            data: {
                password: newHashedPassword,
            },
        });

        return { message: 'Password updated successfully' };
    }

    async forgotPassword(forgotPasswordDto: ForgotPasswordDto)
    {
        const { email } = forgotPasswordDto;
        // Check that user exists
        const user = await this.databaseService.user.findUnique({
            where: {
                email,
            },
        });

        // Note: dont throw error here if user isnt found, as any hacker can check if an email exists on our system by exploiting that
        if (user)
        {
            // incase user repetitively clicks get reset link, we delete the existing one and replace it with the latest resetToken
            await this.databaseService.resetToken.delete({
                where: {
                    userId: user.id,
                },
            });
            // If user exists, generate password reset link
            const resetToken = nanoid(64);
            const expiryDate = new Date();
            expiryDate.setHours(expiryDate.getHours() + 1);
            await this.databaseService.resetToken.create({
                data: {
                    token: resetToken,
                    userId: user.id,
                    expiryDate,
                },
            });
            // Send the link to the user by email (using nodemailer, ses (aws), etc)
            this.mailService.sendPasswordResetEmail(email, resetToken);
        }

        // User exists or not return this
        return {
            message:
                'If the user exists, a password reset email has been sent.',
        };
    }

    async resetPassword(resetPasswordDto: ResetPasswordDto)
    {
        const { resetToken, newPassword } = resetPasswordDto;
        // Find a valid reset token entry in db, also delete it after its used
        const token = await this.databaseService.resetToken.findUnique({
            where: {
                token: resetToken,
            },
        });

        await this.databaseService.resetToken.delete({
            where: {
                token: resetToken,
            },
        });

        if (!token || token.expiryDate < new Date())
        {
            throw new UnauthorizedException('Invalid link');
        }

        // Change user password (MAKE SURE TO HASH)
        const user = await this.databaseService.user.findUnique({
            where: {
                id: token.userId,
            },
        });

        if (!user)
        {
            //small safety check
            throw new NotFoundException('User Not Found');
        }

        const newHashedPassword = await bcrypt.hash(newPassword, 10);
        await this.databaseService.user.update({
            where: {
                id: token.userId,
            },
            data: {
                password: newHashedPassword,
            },
        });

        return { message: 'Password updated successfully' };
    }

    async refreshTokens(refreshTokenDto: RefreshTokenDto)
    {
        const { refreshToken } = refreshTokenDto;
        // Verify refresh token exists and hasn't expired
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
        // Delete old refreshToken and save the new to db
        await this.databaseService.refreshToken.delete({
            where: {
                token: refreshToken,
            },
        });

        // Obtain userId from that refresh token, and generateUserTokens
        return this.generateUserTokens(token.userId);
    }

    async generateUserTokens(userId)
    {
        const accessToken = this.jwtService.sign(
            { userId },
            { expiresIn: '24h' },
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
        expiryDate.setDate(expiryDate.getDate() + 7);
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
