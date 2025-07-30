import { IsNotEmpty, IsString, Matches, MinLength } from 'class-validator';

export class ResetPasswordDto
{
    @IsString()
    resetToken: string;

    @IsString()
    @IsNotEmpty()
    @MinLength(6)
    @Matches(/^(?=.*[0-9])/, {
        message: 'Password must contain atleast one number',
    })
    newPassword: string;
}
