import { IsNotEmpty, IsString, Matches, MinLength } from 'class-validator';

export class ChangePasswordDto
{
    @IsString()
    @IsNotEmpty()
    oldPassword: string;

    @IsString()
    @IsNotEmpty()
    @MinLength(6)
    @Matches(/^(?=.*[0-9])/, {
        message: 'Password must contain atleast one number',
    })
    newPassword: string;
}
